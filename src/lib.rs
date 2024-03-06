// aes-256
use aes_gcm::{Aes256Gcm, aead::OsRng, AeadCore};

// log
use log::{debug,warn,info};

// base64
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64engine, Engine as _};

// duration
use std::time::Duration;

// arc
use std::sync::Arc;
use std::vec;

// proxy-wasm
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// jwt
use jwt_simple::prelude::*;

// url
use url::{form_urlencoded, Url};

/// This module contains logic to parse and save the current authorization state in a cookie
mod cookie;
use cookie::{AuthorizationState, Session};

/// This module contains the structs of the `PluginConfiguration` and `OpenIdConfig`
mod config;
use config::{OpenIdConfig, PluginConfiguration};

/// This module contains the OIDC discovery and JWKs loading logic
mod discovery;

/// This module contains the responses for the OIDC discovery and jwks endpoints
mod responses;
use responses::Callback;

/// The PauseRequests Context is the filter struct which is used when the filter is not configured.
/// All requests are paused and queued by the RootContext. Once the filter is configured, the
/// request is resumed by the RootContext.
struct PauseRequests {
    /// Original path of the request
    original_path: Option<String>,
}

/// The context is used to process incoming HTTP requests when the filter is not configured.
impl HttpContext for PauseRequests {

    /// This function is called when the request headers are received. As the filter is not
    /// configured, the request is paused and queued by the RootContext. Once the filter is
    /// configured, the request is resumed by the RootContext.
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        warn!("filter not ready, pausing request");

        // Get the original path from the request headers
        self.original_path = Some(self.get_http_request_header(":path").unwrap_or("/".to_string()));

        Action::Pause
    }

    /// When the filter is configured, this function is called once the root context resumes the
    /// request. This function sends a redirect to create a new context for the configured filter.
    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {

        info!("filter now ready, sending redirect");

        // Send a redirect to the original path
        self.send_http_response(307,
            vec![
            // Redirect to the requested path
            ("location", self.original_path.as_ref().unwrap()),
            // Disable caching
            ("Cache-Control", "no-cache"),
        ],
        Some(b"Filter is ready now."));
        Action::Continue
    }
}

impl Context for PauseRequests {}

/// The ConfiguredOidc is the main filter struct and responsible for the OIDC authentication flow.
/// Requests arriving are checked for a valid cookie. If the cookie is valid, the request is
/// forwarded. If the cookie is not valid, the request is redirected to the `authorization endpoint`.
struct ConfiguredOidc {
    /// The configuration of the filter which mainly contains the open id configuration and the
    /// keys to validate the JWT
    pub open_id_config: Arc<OpenIdConfig>,
    /// Plugin configuration parsed from the envoy configuration
    pub plugin_config: Arc<PluginConfiguration>,
    /// Token id of the current request
    pub token_id: Option<u32>,
    /// AES256 Cipher
    pub cipher: Aes256Gcm,
}

/// The context is used to process incoming HTTP requests when the filter is configured.
/// 1. Check if the request matches any of the exclude hosts, paths, urls. If so, forward the request.
/// 2. If the request is for the OIDC callback, dispatch the request to the token endpoint.
/// 3. If the request contains a cookie, validate the cookie and forward the request.
/// 4. Else, redirect the request to the `authorization endpoint`.
impl HttpContext for ConfiguredOidc {

    /// This function is called when the request headers are received.
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {

        // Check if the host regex matches one of the exclude hosts. If so, forward the request.
        let host = self.get_host().unwrap_or_default();

        if self.plugin_config.exclude_hosts.iter().any(|x| x.is_match(&host)) {
            debug!("Host {} is excluded. Forwarding request.", host);
            self.filter_proxy_cookies();
            return Action::Continue;
        }

        // If the path is one of the exclude paths, forward the request
        let path = self.get_http_request_header(":path").unwrap_or_default();
        if self.plugin_config.exclude_paths.iter().any(|x| x.is_match(&path)) {
            debug!("Path {} is excluded. Forwarding request.", path);
            self.filter_proxy_cookies();
            return Action::Continue;
        }

        let url = Url::parse(&format!("{}{}", host, path)).unwrap_or(Url::parse("http://example.com").unwrap());
        if self.plugin_config.exclude_urls.iter().any(|x| x.is_match(&url.as_str())) {
            debug!("Url {} is excluded. Forwarding request.", url.as_str());
            self.filter_proxy_cookies();
            return Action::Continue;
        }

        // exchanges the code for a token. The response is caught in on_http_call_response.
        // If the dispatch fails, a 503 is returned.
        if path.starts_with(Url::parse(&self.plugin_config.redirect_uri).unwrap().path()) {
            match self.exchange_code_for_token(path) {
                Ok(_) => {
                    return Action::Pause;
                },
                Err(e) => {
                    warn!("token exchange failed: {}", e);
                    self.send_http_response(503,
                        vec![
                            ("Cache-Control", "no-cache"),
                        ],
                    Some(b"Token exchange failed."));
                }
            }
            return Action::Pause;
        }

        // Validate the cookie and forward the request if the cookie is valid
        match self.validate_cookie() {
            Ok(auth_state) => {
                // Forward access token in header, if configured
                if let Some(header_name) = &self.plugin_config.access_token_header_name {
                    // Get access token
                    let access_token = &auth_state.access_token;
                    // Forward access token in header
                    self.add_http_request_header(
                        &header_name,
                        format!("{}{}",
                            self.plugin_config.access_token_header_prefix.as_ref().unwrap(),
                            access_token
                    ).as_str());
                }

                // Forward id token in header, if configured
                if let Some(header_name) = &self.plugin_config.id_token_header_name {
                    // Get id token
                    let id_token = &auth_state.id_token;
                    // Forward id token in header
                    self.add_http_request_header(
                        &header_name,
                        format!("{}{}",
                            self.plugin_config.id_token_header_prefix.as_ref().unwrap(),
                            id_token
                    ).as_str());
                }

                self.filter_proxy_cookies();

                // Allow request to pass
                return Action::Continue;
            },
            Err(e) => {
                warn!("cookie validation failed: {}", e);
            }
        }

        // Redirect to `authorization_endpoint` if no cookie is found or previous cases have returned an error.
        // Pausing the request is necessary to create a new context after the redirect.
        self.redirect_to_authorization_endpoint();

        Action::Pause
    }
}

/// This context is used to process HTTP responses from the token endpoint.
impl Context for ConfiguredOidc {

    /// This function catches the response from the token endpoint.
    fn on_http_call_response(&mut self, token_id: u32, _: usize, body_size: usize, _: usize) {

        // Store the token in the cookie
        match self.store_token_in_cookie(token_id, body_size) {
            Ok(_) => {
                debug!("token stored in cookie");
            },
            Err(e) => {
                warn!("storing token in cookie failed: {}", e);
                // Send a 503 if storing the token in the cookie failed
                self.send_http_response(503,
                    vec![
                        ("Cache-Control", "no-cache"),
                    ],
                Some(b"Storing token in cookie failed."));
            }
        }
    }
}

/// Helper functions for the OIDCFlow struct.
impl ConfiguredOidc {

    /// Get the cookie of the HTTP request by name
    /// The cookie is searched in the request headers. If the cookie is found, the value is returned.
    /// If the cookie is not found, None is returned.
    fn get_cookie(&self, name: &str) -> Option<String> {
        let headers = self.get_http_request_headers();
        for (key, value) in headers.iter() {
            if key.to_lowercase().trim() == "cookie" {
                let cookies: Vec<_> = value.split(";").collect();
                for cookie_string in cookies {
                    let cookie_name_end = cookie_string.find('=').unwrap_or(0);
                    let cookie_name = &cookie_string[0..cookie_name_end];
                    if cookie_name.trim() == name {
                        return Some(
                            cookie_string[(cookie_name_end + 1)..cookie_string.len()].to_owned(),
                        );
                    }
                }
            }
        }
        return None;
    }

    /// Get the host of the HTTP request
    /// The host is searched in the request headers. If the host is found, the value is returned.
    fn get_host(&self) -> Option<String> {

        self.get_http_request_header(":authority")
            .or_else(|| self.get_http_request_header("host"))
            .or_else(|| self.get_http_request_header("x-forwarded-host"))
    }

    /// Filter non proxy cookies by checking the cookie name.
    /// This function removes all cookies from the request that do not match the cookie name to prevent
    /// the cookie from being forwarded to the upstream service.
    fn filter_proxy_cookies(&self) {

        // Get all cookies
        let all_cookies = self.get_http_request_header("cookie").unwrap_or_default();

        // Remove non proxy cookies from request
        let filtered_cookies = all_cookies.split(";")
            .filter(|x| !x.contains(&self.plugin_config.cookie_name))
            .filter(|x| !x.contains("nonce"))
            .collect::<Vec<&str>>()
            .join(";");

        // Set the cookie header
        self.set_http_request_header("Cookie", Some(&filtered_cookies));
    }

    /// Parse the cookie and validate the token.
    /// The cookie is parsed into the `AuthorizationState` struct. The token is validated using the
    /// `validate_token` function. If the token is valid, this function returns Ok(()). If the token
    /// is invalid, this function returns Err(String) and redirects the requester to the `authorization endpoint`.
    fn validate_cookie(&self) -> Result<AuthorizationState, String> {

        debug!("cookie found, checking validity");

        // Get cookie and nonce
        let cookie = self.get_session_cookie_as_string();
        let nonce = match self.get_cookie("nonce") {
            Some(nonce) => nonce,
            None => {
                return Err("No nonce found in cookie".to_string());
            }
        };

        // Try to parse and decrypt the cookie and handle the result
        match Session::decode_and_decrypt(cookie, self.cipher.to_owned(), nonce) {

            // If the cookie can be parsed, this means that the cookie is trusted because modifications would have
            // corrupted the encrypted state. Token validation is only performed if the configuration option is set.
            Ok(session) => {

                // Only validate the token if the configuration option is set
                match self.plugin_config.token_validation {
                    true => {

                        // Get authorization state from session
                        let auth_state = session.authorization_state.unwrap(); // TODO: Idiomatically handle the error

                        // Validate token
                        match self.validate_token(&auth_state.id_token) {
                            // If the token is valid, this filter passes the request
                            Ok(_) => {
                                debug!("token is valid, passing request");
                                Ok(auth_state)
                            }
                            // If the token is invalid, the error is returned and the requester is redirected to the `authorization endpoint`
                            Err(e) => {
                                return Err(format!("token validation failed: {:?}", e));
                            }
                        }
                    }
                    false => {
                        Ok(session.authorization_state.unwrap())
                    }
                }
            }
            // If the cookie cannot be parsed, this filter redirects the requester to the `authorization_endpoint`
            Err(err) => {
                return Err(format!("Authorisation state couldn't be loaded from the cookie: {:?}",err));
            }
        }
    }


    /// Validate the token using the JWT library.
    /// This function checks for the correct issuer and audience and verifies the signature with the
    /// public keys loaded from the JWKs endpoint.
    /// * `token` - The token to be validated
    fn validate_token(&self, token: &str) -> Result<(), String> {

        // Define allowed issuers and audiences
        let mut allowed_issuers = HashSet::new();
        allowed_issuers.insert(self.open_id_config.issuer.to_string());
        let mut allowed_audiences = HashSet::new();
        allowed_audiences.insert(self.plugin_config.audience.to_string());

        // Define verification options
        let mut verification_options = VerificationOptions::default();
        verification_options.allowed_audiences = Some(allowed_audiences);
        verification_options.allowed_issuers = Some(allowed_issuers);

        // Iterate over all public keys
        for public_key in &self.open_id_config.public_keys {

            // Perform the validation
            let validation_result =
                public_key.verify_token(&token, verification_options.to_owned());

            // Check if the token is valid, the aud and iss are correct and the signature is valid.
            match validation_result {
                Ok(_) => {
                    debug!("token validated with key");
                    return Ok(());
                }
                Err(_) => {
                    continue;
                }
            }
        }
        return Err("No key worked".to_string());

    }

    /// Exchange the code for a token using the token endpoint.
    /// This function is called when the user is redirected back to the callback URL.
    /// The code is extracted from the URL and exchanged for a token using the token endpoint.
    /// * `path` - The path of the request
    fn exchange_code_for_token(&mut self, path: String) -> Result<(), String>{

        debug!("received request for OIDC callback");

        // Get Query String from URL
        let query = path.split("?").last().unwrap_or_default();

        // Get state from query
        let callback_params = match serde_urlencoded::from_str::<Callback>(&query) {
            Ok(callback) => callback,
            Err(e) => {
                return Err(e.to_string());
            }
        };

        // Get cookie
        let encoded_cookie = self.get_session_cookie_as_string();

        // Get nonce from cookie
        let encoded_nonce = match self.get_cookie("nonce") {
            Some(nonce) => nonce,
            None => {
                return Err("No nonce found in cookie".to_string());
            }
        }; // TODO: Idiomatically handle the error
        debug!("nonce from cookie: {}", encoded_nonce);

        // Get session
        let session = match Session::decode_and_decrypt(encoded_cookie, self.cipher.clone(), encoded_nonce) {
            Ok(session) => session,
            Err(e) => {
                return Err(format!("Failed to decode and decrypt cookie: {:?}", e));
            }
        }; // TODO: Idiomatically handle the error

        // Get state and code from query
        let state = callback_params.state;
        let code = callback_params.code;
        debug!("authorization code: {}", code);

        // Compare state
        if state != session.state {
            warn!("state does not match.");
            return Err("state does not match.".to_string());
        }

        // Hardcoded values for request to token endpoint
        let client_id = &self.plugin_config.client_id;
        let client_secret = &self.plugin_config.client_secret;

        // Encode client_id and client_secret and build the Authorization header using base64encoding
        let encoded = base64engine.encode(format!("{client_id}:{client_secret}").as_bytes());
        let auth = format!("Basic {}", encoded);

        // Get code verifier from cookie
        let code_verifier = session.code_verifier;

        // Build the request body for the token endpoint
        let data = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code_verifier", &code_verifier)
            .append_pair("code", &code)
            .append_pair("redirect_uri", self.plugin_config.redirect_uri.as_str())
            .append_pair("state", &state)
            .finish();

        // Get path from token endpoint
        let token_endpoint = self.open_id_config.token_endpoint.path();

        // Dispatch request to token endpoint using built-in envoy function
        debug!("sending data to token endpoint: {}", data);
        match self.dispatch_http_call(
            "oidc",
            vec![
                (":method", "POST"),
                (":path", &token_endpoint),
                (":authority", &self.plugin_config.authority),
                ("Authorization", &auth),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            Some(data.as_bytes()),
            vec![],
            Duration::from_secs(10),
        ) {
            // If the request is dispatched successfully, this filter pauses the request
            Ok(id) => {
                self.token_id = Some(id);
                Ok(())
            }
            // If the request fails, this filter logs the error and pauses the request
            Err(err) => {
               return Err(format!("Failed to dispatch HTTP request to Token Endpoint: {:?}", err));
            }
        }
    }

    /// Store the token from the token response in a cookie.
    /// Parse the token with the `AuthorizationState` struct and store it in an encoded cookie.
    /// Then, redirect the requester to the original URL.
    fn store_token_in_cookie(&mut self, token_id: u32, body_size: usize) -> Result<(), String> {
        // Assess token id
        if self.token_id != Some(token_id) {
            warn!("Token id does not match.");
            return Err("Token id does not match.".to_string());
        }

        // Check if the response is valid. If its not 200, investigate the response
        // and log the error.
        if self.get_http_call_response_header(":status") != Some("200".to_string()) {
            // Get body of response
            match self.get_http_call_response_body(0, body_size) {
                Some(body) => {
                    // Decode body
                    match String::from_utf8(body) {
                        Ok(decoded) => {
                            return Err(format!("Token response is not valid: {:?}", decoded));
                        }
                        // If decoding fails, log the error
                        Err(_) => {
                            return Err(format!("Token could not be decoded"));
                        }
                    }
                }
                // If no body is found, log the error
                None => {
                    return Err(format!(
                        "No body in token response with invalid status code."
                    ));
                }
            }
        }

        // Catching token response from token endpoint. Previously we checked for the status code and
        // the body, so we can assume that the response is valid.
        match self.get_http_call_response_body(0, body_size) {
            Some(body) => {
                debug!("token response: {:?}", body);

                // Get nonce from cookie
                let encoded_nonce = self.get_cookie("nonce").unwrap_or_default();

                // Get cookie
                let encoded_cookie = self.get_session_cookie_as_string();

                // Get session from cookie
                let session = match Session::decode_and_decrypt(encoded_cookie, self.cipher.clone(), encoded_nonce.clone()) {
                    Ok(session) => session,
                    Err(e) => {
                        return Err(format!("Failed to decode and decrypt cookie: {:?}", e.as_str()));
                    }
                }; // TODO: Idiomatically handle the error

                // Create authorization state from token response
                let authorization_state = serde_json::from_slice::<AuthorizationState>(&body).unwrap(); // TODO: Idiomatically handle the error

                // Create new session
                let new_session = cookie::Session{
                    authorization_state: Some(authorization_state),
                    original_path: session.original_path.clone(),
                    code_verifier: session.code_verifier.clone(),
                    state: session.state.clone(),
                }.encrypt_and_encode(self.cipher.clone(), encoded_nonce);

                // Get original path
                let original_path = session.original_path.clone();

                // Build cookie values
                let set_cookie_values = Session::make_cookie_values(
                    new_session.to_owned(),
                    self.plugin_config.cookie_name.clone(),
                    self.plugin_config.cookie_duration,
                    self.get_number_of_cookies() as u64
                );

                // Build cookie headers
                let mut set_cookie_headers = Session::make_set_cookie_headers(&set_cookie_values);

                // Set the location header to the original path
                let location_header = ("Location", original_path.as_str());
                set_cookie_headers.push(location_header);

                // Redirect back to the original URL and set the cookie.
                self.send_http_response(
                    307,
                    set_cookie_headers.to_vec(),
                    Some(b"Redirecting..."),
                );
                Ok(())
            },
            // If no body is found, return the error
            None => {
                Err(format!("no body in token response with invalid status code"))
            }
        }
    }

    /// Redirect to the` authorization endpoint` by sending a HTTP response with a 307 status code.
    /// The original path is encoded and stored in a cookie as well as the PKCE code verifier.
    fn redirect_to_authorization_endpoint(&self) -> Action {

        debug!("no cookie found or invalid, redirecting to authorization endpoint");

        // Original path
        let original_path = self.get_http_request_header(":path").unwrap_or_default();

        // Generate nonce and encode it
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let encoded_nonce = base64engine.encode(nonce.as_slice());

        // Generate PKCE code verifier and challenge
        let pkce_verifier = pkce::code_verifier(128);
        let pkce_verifier_string = String::from_utf8(pkce_verifier.clone()).unwrap();
        let pkce_challenge = pkce::code_challenge(&pkce_verifier);

        // Generate state
        let state_string = String::from_utf8(pkce::code_verifier(128)).unwrap();

        // Create session struct
        let session = cookie::Session{
            authorization_state: None,
            original_path,
            code_verifier: pkce_verifier_string,
            state: state_string.clone(),
        }.encrypt_and_encode(self.cipher.clone(), encoded_nonce.clone());

        // Build cookie values
        let set_cookie_values = Session::make_cookie_values(
            session,
            self.plugin_config.cookie_name.clone(),
            self.plugin_config.cookie_duration,
            self.get_number_of_cookies() as u64
        );

        // Build cookie headers
        let mut headers = Session::make_set_cookie_headers(&set_cookie_values);

        // Build nonce cookie value
        let nonce_cookie_value = &format!("nonce={}; Max-Age={}; HttpOnly; Secure", &encoded_nonce, self.plugin_config.cookie_duration);

        // Add nonce cookie to headers
        headers.push(("Set-Cookie", nonce_cookie_value));

        // Build URL
        let url = Url::parse_with_params(
            self.open_id_config.auth_endpoint.as_str(),
            &[
                    ("response_type", "code"),
                    ("code_challenge", &pkce_challenge),
                    ("code_challenge_method", "S256"),
                    ("state", &state_string),
                    ("client_id", &self.plugin_config.client_id),
                    ("redirect_uri",&self.plugin_config.redirect_uri.as_str()),
                    ("scope", &self.plugin_config.scope),
                    ("claims", &self.plugin_config.claims),
                ],
            )
            .unwrap();

        // Add location header
        headers.push(("Location", url.as_str()));

        // Send HTTP response
        self.send_http_response(
            307,
            // Redirect to `authorization endpoint` along with the cookie
            headers.to_vec(),
            Some(b"Redirecting..."),
            );
            return Action::Pause;
    }

    /// Helper function to get the session cookie as a string by getting the cookie from the request
    /// headers and concatenating all cookie parts.
    pub fn get_session_cookie_as_string(&self) -> String {

        // Find all cookies that have the cookie_name, split them by ; and remove the name from the cookie
        // as well as the leading =. Then join the cookie values together again.
        let cookie = self.get_http_request_header("cookie").unwrap_or_default();

        // Split cookie by ; and filter for the cookie name.
        let cookie = cookie.split(";")
            .filter(|x| x.contains(self.plugin_config.cookie_name.as_str()))
            // Then split by = and get the second element.
            .map(|x| x.split("=").collect::<Vec<&str>>()[1])
            .collect::<Vec<&str>>()
            // Join the cookie values together again.
            .join("");

        return cookie;
    }

    /// Helper function to get the number of cookies from the request headers.
    pub fn get_number_of_cookies(&self) -> usize {
        let cookie = self.get_http_request_header("cookie").unwrap_or_default();
        cookie.split(";").count()
    }
}
