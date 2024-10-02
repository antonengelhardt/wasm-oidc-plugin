// arc
use std::sync::Arc;
use std::vec;

// base64
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64engine, Engine as _};

// duration
use std::time::Duration;

// jwt
use jwt_simple::prelude::*;

// log
use log::{debug, info, warn};

// proxy-wasm
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

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

/// This module contains the error types for the plugin
mod error;
use error::PluginError;

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
        warn!("plugin not ready, pausing request");

        // Get the original path from the request headers
        self.original_path = Some(
            self.get_http_request_header(":path")
                .unwrap_or("/".to_string()),
        );

        Action::Pause
    }

    /// When the filter is configured, this function is called once the root context resumes the
    /// request. This function sends a redirect to create a new context for the configured filter.
    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        info!("filter now ready, sending redirect");

        // Send a redirect to the original path
        self.send_http_response(
            307,
            vec![
                // Redirect to the requested path
                ("location", self.original_path.as_ref().unwrap()),
                // Disable caching
                ("Cache-Control", "no-cache"),
            ],
            Some(b"Filter is ready now."),
        );
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
}

/// The context is used to process incoming HTTP requests when the filter is configured.
/// 1. Check if the request matches any of the exclude hosts, paths, urls. If so, forward the request.
/// 2. If the request is for the OIDC callback, dispatch the request to the token endpoint.
/// 3. If the request contains a cookie, validate the cookie and forward the request.
/// 4. Else, redirect the request to the `authorization endpoint`.
impl HttpContext for ConfiguredOidc {
    /// This function is called when the request headers are received.
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        // Get the host, path and scheme from the request headers
        let host = self.get_host().unwrap_or_default();
        debug!("host: {}", host);
        let path = self.get_http_request_header(":path").unwrap_or_default();
        debug!("path: {}", path);
        let scheme = self
            .get_http_request_header(":scheme")
            .unwrap_or("http".to_string());
        debug!("scheme: {}", scheme);

        // Health check
        if path == "/plugin-health" {
            self.send_http_response(200, vec![], Some(b"OK"));
            return Action::Pause;
        }

        // If the host is one of the exclude hosts, forward the request
        if self
            .plugin_config
            .exclude_hosts
            .iter()
            .any(|x| x.is_match(&host))
        {
            debug!("host {} is excluded, forwarding request.", host);
            self.filter_proxy_cookies();
            return Action::Continue;
        }

        // If the path is one of the exclude paths, forward the request
        if self
            .plugin_config
            .exclude_paths
            .iter()
            .any(|x| x.is_match(&path))
        {
            debug!("path {} is excluded, forwarding request.", path);
            self.filter_proxy_cookies();
            return Action::Continue;
        }

        // Parse the URL and check if it is excluded
        let url = Url::parse(&format!("{}://{}{}", scheme, host, path))
            .unwrap_or(Url::parse("http://example.com").unwrap());
        debug!("url: {}", url);

        if self
            .plugin_config
            .exclude_urls
            .iter()
            .any(|x| x.is_match(url.as_str()))
        {
            debug!("url {} is excluded, forwarding request.", url.as_str());
            self.filter_proxy_cookies();
            return Action::Continue;
        }

        // If the request is for the OIDC callback, e.g the code is returned, this filter
        // exchanges the code for a token. The response is caught in on_http_call_response.
        // If the dispatch fails, a 503 is returned.
        if path.starts_with(self.plugin_config.redirect_uri.path()) {
            match self.exchange_code_for_token(path) {
                Ok(_) => {
                    return Action::Pause;
                }
                Err(e) => {
                    warn!("token exchange failed: {}", e);
                    self.send_http_response(
                        503,
                        vec![("Cache-Control", "no-cache"),
                        ("Content-Type", "text/html")],
                        Some(b"<div style=\"text-align: center; margin-top: 20%; font-family: Arial, sans-serif;\">
                        <h1>503</h1>
                        <h2>Token exchange failed</h2>
                        <p>Please try again, delete your cookies or contact your system administrator.</p>
                        </div>"),
                    );
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
                        header_name,
                        format!(
                            "{}{}",
                            self.plugin_config
                                .access_token_header_prefix
                                .as_ref()
                                .unwrap(),
                            access_token
                        )
                        .as_str(),
                    );
                }

                // Forward id token in header, if configured
                if let Some(header_name) = &self.plugin_config.id_token_header_name {
                    // Get id token
                    let id_token = &auth_state.id_token;
                    // Forward id token in header
                    self.add_http_request_header(
                        header_name,
                        format!(
                            "{}{}",
                            self.plugin_config.id_token_header_prefix.as_ref().unwrap(),
                            id_token
                        )
                        .as_str(),
                    );
                }

                self.filter_proxy_cookies();

                // Allow request to pass
                return Action::Continue;
            }
            Err(e) => match e {
                // disable logging for these errors
                PluginError::SessionCookieNotFoundError => {}
                PluginError::NonceCookieNotFoundError => {}
                _ => warn!("cookie validation failed: {}", e),
            },
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
            }
            Err(e) => {
                warn!("storing token in cookie failed: {}", e);
                // Send a 503 if storing the token in the cookie failed
                self.send_http_response(
                    503,
                    vec![("Cache-Control", "no-cache"),
                    ("Content-Type", "text/html")],
                    Some(b"<div style=\"text-align: center; margin-top: 20%; font-family: Arial, sans-serif;\">
                    <h1>503</h1>
                    <h2>Storing Token in Cookie failed</h2>
                    <p>Please try again, delete your cookies or contact your system administrator.</p>
                    </div>",
                    ),
                );
            }
        }
    }
}

/// Helper functions for the ConfiguredOidc struct.
impl ConfiguredOidc {
    /// Get the cookie of the HTTP request by name
    /// The cookie is searched in the request headers. If the cookie is found, the value is returned.
    /// If the cookie is not found, None is returned.
    fn get_cookie(&self, name: &str) -> Option<String> {
        let headers = self.get_http_request_headers();
        for (key, value) in headers.iter() {
            if key.to_lowercase().trim() == "cookie" {
                let cookies: Vec<_> = value.split(';').collect();
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
        None
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
        // Check if the filter_plugin_cookies option is set
        if !self.plugin_config.filter_plugin_cookies {
            return;
        }

        // Get all cookies
        let all_cookies = self.get_http_request_header("cookie").unwrap_or_default();

        // Remove non proxy cookies from request
        let filtered_cookies = all_cookies
            .split(';')
            .filter(|x| !x.contains(&self.plugin_config.cookie_name))
            .filter(|x| !x.contains(&format!("{}-nonce", self.plugin_config.cookie_name)))
            .collect::<Vec<&str>>()
            .join(";");

        // Set the cookie header
        self.set_http_request_header("Cookie", Some(&filtered_cookies));
    }

    /// Parse the cookie and validate the token.
    /// The cookie is parsed into the `AuthorizationState` struct. The token is validated using the
    /// `validate_token` function. If the token is valid, this function returns Ok(()). If the token
    /// is invalid, this function returns Err(String) and redirects the requester to the `authorization endpoint`.
    fn validate_cookie(&self) -> Result<AuthorizationState, PluginError> {
        // Get cookie and nonce
        let cookie = self.get_session_cookie_as_string()?;
        let nonce = self.get_nonce()?;

        // Try to parse and decrypt the cookie and handle the result
        match Session::decode_and_decrypt(
            cookie,
            self.plugin_config.aes_key.reveal().clone(),
            nonce,
        ) {
            // If the cookie can be parsed, this means that the cookie is trusted because modifications would have
            // corrupted the encrypted state. Token validation is only performed if the configuration option is set.
            Ok(session) => {
                // Only validate the token if the configuration option is set
                match self.plugin_config.token_validation {
                    true => {
                        // Get authorization state from session
                        let auth_state = match session.authorization_state {
                            Some(auth_state) => auth_state,
                            None => {
                                return Err(PluginError::AuthorizationStateNotFoundError);
                            }
                        };

                        // Validate token
                        match self.validate_token(&auth_state.id_token) {
                            // If the token is valid, this filter passes the request
                            Ok(_) => {
                                debug!("token is valid, passing request");
                                Ok(auth_state)
                            }
                            // If the token is invalid, the error is returned and the requester is redirected to the `authorization endpoint`
                            Err(e) => Err(PluginError::TokenValidationError(e.into())),
                        }
                    }
                    false => match session.authorization_state {
                        Some(auth_state) => Ok(auth_state),
                        // If no authorization state is found, return an error
                        None => Err(PluginError::CookieValidationError(
                            "No authorization state found".to_string(),
                        )),
                    },
                }
            }
            // If the cookie cannot be parsed, this filter redirects the requester to the `authorization_endpoint`
            Err(e) => Err(PluginError::CookieValidationError(e.to_string())),
        }
    }

    /// Validate the token using the JWT library.
    /// This function checks for the correct issuer and audience and verifies the signature with the
    /// public keys loaded from the JWKs endpoint.
    fn validate_token(&self, token: &str) -> Result<(), PluginError> {
        // Define allowed issuers and audiences
        let mut allowed_issuers = HashSet::new();
        // remove last slash from issuer url
        allowed_issuers.insert(self.open_id_config.issuer.clone());
        let mut allowed_audiences = HashSet::new();
        allowed_audiences.insert(self.plugin_config.audience.to_string());

        // Define verification options
        let verification_options = VerificationOptions {
            allowed_issuers: Some(allowed_issuers),
            allowed_audiences: Some(allowed_audiences),
            ..Default::default()
        };

        // Iterate over all public keys
        for public_key in &self.open_id_config.public_keys {
            // Perform the validation
            let validation_result = public_key.verify_token(token, verification_options.to_owned());

            // Check if the token is valid, the aud and iss are correct and the signature is valid.
            match validation_result {
                Ok(_) => return Ok(()),
                Err(e) => {
                    debug!("token validation failed: {:?}", e);
                    continue;
                }
            }
        }
        Err(PluginError::NoKeyError)
    }

    /// Exchange the code for a token using the token endpoint.
    /// This function is called when the user is redirected back to the callback URL.
    /// The code is extracted from the URL and exchanged for a token using the token endpoint.
    /// * `path` - The path of the request
    fn exchange_code_for_token(&mut self, path: String) -> Result<(), PluginError> {
        debug!("received request for OIDC callback");

        // Get Query String from URL
        let query = path.split('?').last().unwrap_or_default();

        // Get state from query
        let callback_params = serde_urlencoded::from_str::<Callback>(query)?;

        // Get cookie and nonce
        let encoded_cookie = self.get_session_cookie_as_string()?;
        let encoded_nonce = self.get_nonce()?;

        // Get session
        let session = Session::decode_and_decrypt(
            encoded_cookie,
            self.plugin_config.aes_key.reveal().clone(),
            encoded_nonce,
        )?;

        // Get state and code from query
        let code = callback_params.code;
        debug!("authorization code: {}", code);
        let state = callback_params.state;
        debug!("client state: {}", state);
        debug!("cookie state: {}", session.state);

        // Compare state
        if state != session.state {
            return Err(PluginError::StateMismatchError);
        }

        // Encode client_id and client_secret and build the Authorization header using base64encoding
        let auth = format!(
            "Basic {}",
            base64engine.encode(
                format!(
                    "{}:{}",
                    &self.plugin_config.client_id,
                    &self.plugin_config.client_secret.reveal()
                )
                .as_bytes()
            )
        );

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
                (":path", token_endpoint),
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
            Err(_) => Err(PluginError::DispatchError),
        }
    }

    /// Store the token from the token response in a cookie.
    /// Parse the token with the `AuthorizationState` struct and store it in an encoded and encrypted cookie.
    /// Then, redirect the requester to the original URL.
    fn store_token_in_cookie(
        &mut self,
        token_id: u32,
        body_size: usize,
    ) -> Result<(), PluginError> {
        // Assess token id
        if self.token_id != Some(token_id) {
            return Err(PluginError::TokenIdMismatchError);
        }

        // Check if the response is valid. If its not 200, investigate the response
        // and log the error.
        if self.get_http_call_response_header(":status") != Some("200".to_string()) {
            // Get body of response
            match self.get_http_call_response_body(0, body_size) {
                Some(body) => {
                    // Decode body
                    match String::from_utf8(body) {
                        Ok(decoded) => return Err(PluginError::TokenResponseFormatError(decoded)),
                        // If decoding fails, log the error
                        Err(e) => return Err(PluginError::Utf8Error(e)),
                    }
                }
                // If no body is found, log the error
                None => return Err(PluginError::NoBodyError),
            }
        }

        // Catching token response from token endpoint. Previously we checked for the status code and
        // the body, so we can assume that the response is valid.
        match self.get_http_call_response_body(0, body_size) {
            Some(body) => {
                // Get nonce and cookie
                let encoded_cookie = self.get_session_cookie_as_string()?;
                let encoded_nonce = self.get_nonce()?;

                // Get session from cookie
                let mut session = Session::decode_and_decrypt(
                    encoded_cookie,
                    self.plugin_config.aes_key.reveal().clone(),
                    encoded_nonce,
                )?;

                // Create authorization state from token response
                let authorization_state = serde_json::from_slice::<AuthorizationState>(&body)?;

                // Add authorization state to session
                session.authorization_state = Some(authorization_state);

                // Create new session
                let (new_session, new_nonce) =
                    session.encrypt_and_encode(self.plugin_config.aes_key.reveal().clone())?;

                // Get original path
                let original_path = session.original_path.clone();

                // Build cookie values
                let set_cookie_values = Session::make_cookie_values(
                    &new_session,
                    &new_nonce,
                    self.plugin_config.cookie_name.as_str(),
                    self.plugin_config.cookie_duration,
                    self.get_number_of_cookies() as u64,
                );

                // Build cookie headers
                let mut set_cookie_headers = Session::make_set_cookie_headers(&set_cookie_values);

                // Set the location header to the original path
                let location_header = ("Location", original_path.as_str());
                set_cookie_headers.push(location_header);

                // Redirect back to the original URL and set the cookie.
                self.send_http_response(307, set_cookie_headers, Some(b"Redirecting..."));
                Ok(())
            }
            // If no body is found, return the error
            None => Err(PluginError::CookieStoreError(
                "No body in response".to_string(),
            )),
        }
    }

    /// Redirect to the` authorization endpoint` by sending a HTTP response with a 307 status code.
    /// The original path is encoded and stored in a cookie as well as the PKCE code verifier.
    fn redirect_to_authorization_endpoint(&self) -> Action {
        debug!("no cookie found or invalid, redirecting to authorization endpoint");

        // Original path
        let original_path = self.get_http_request_header(":path").unwrap_or_default();

        // Generate PKCE code verifier and challenge
        let pkce_verifier = pkce::code_verifier(128);
        let pkce_verifier_string = String::from_utf8(pkce_verifier.clone()).unwrap();
        let pkce_challenge = pkce::code_challenge(&pkce_verifier);

        // Generate state
        let state_string = String::from_utf8(pkce::code_verifier(128)).unwrap();

        // Create session struct
        let (session, nonce) = cookie::Session {
            authorization_state: None,
            original_path,
            code_verifier: pkce_verifier_string,
            state: state_string.clone(),
        }
        .encrypt_and_encode(self.plugin_config.aes_key.reveal().clone())
        .expect("session cookie could not be created");

        // Build cookie values
        let set_cookie_values = Session::make_cookie_values(
            &session,
            &nonce,
            self.plugin_config.cookie_name.as_str(),
            self.plugin_config.cookie_duration,
            self.get_number_of_cookies() as u64,
        );

        // Build cookie headers
        let mut headers = Session::make_set_cookie_headers(&set_cookie_values);

        // Build URL
        let url = Url::parse_with_params(
            self.open_id_config.auth_endpoint.as_str(),
            &[
                ("response_type", "code"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
                ("state", &state_string),
                ("client_id", &self.plugin_config.client_id),
                ("redirect_uri", self.plugin_config.redirect_uri.as_str()),
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
            headers,
            Some(b"Redirecting..."),
        );
        Action::Pause
    }

    /// Helper function to get the session cookie as a string by getting the cookie from the request
    /// headers and concatenating all cookie parts.
    pub fn get_session_cookie_as_string(&self) -> Result<String, PluginError> {
        // Find all cookies that have the cookie_name, split them by ; and remove the name from the cookie
        // as well as the leading =. Then join the cookie values together again.
        let cookie = self
            .get_http_request_header("cookie")
            .ok_or(PluginError::SessionCookieNotFoundError)?;

        // Split cookie by ; and filter for the cookie name.
        let cookies = cookie
            .split(';')
            .filter(|x| x.contains(self.plugin_config.cookie_name.as_str()))
            .filter(|x| !x.contains(format!("{}-nonce", self.plugin_config.cookie_name).as_str()));

        // Check if cookies have values
        for cookie in cookies.clone() {
            if cookie.split('=').collect::<Vec<&str>>().len() < 2 {
                return Err(PluginError::SessionCookieNotFoundError);
            }
        }

        // Then split all cookies by = and get the second element before joining all values together.
        let values = cookies
            .map(|x| x.split('=').collect::<Vec<&str>>()[1])
            .collect::<Vec<&str>>()
            // Join the cookie values together again.
            .join("");

        Ok(values)
    }

    // Get the encoded nonce from the cookie
    pub fn get_nonce(&self) -> Result<String, PluginError> {
        self.get_cookie(format!("{}-nonce", self.plugin_config.cookie_name).as_str())
            .ok_or(PluginError::NonceCookieNotFoundError)
    }

    /// Helper function to get the number of cookies from the request headers.
    pub fn get_number_of_cookies(&self) -> usize {
        let cookie = self.get_http_request_header("cookie").unwrap_or_default();
        cookie.split(';').count()
    }
}
