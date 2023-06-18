// log
use log::{debug,warn,info};

// base64
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64engine, Engine as _};

// regex
use regex::Regex;

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

/// This module contains the structs of the `PluginConfiguration` and `OpenIdConfig`
mod config;
use config::{OpenIdConfig, PluginConfiguration};

/// This module contains the OIDC discovery and JWKs loading logic
mod discovery;

/// This module contains the responses for the OIDC discovery and jwks endpoints
mod responses;

/// The UnconfiguredOidc is the filter struct which is used when the filter is not configured.
/// All requests are paused and queued by the RootContext. Once the filter is configured, the
/// request is resumed by the RootContext.
struct UnconfiguredOidc {
    /// Original path of the request
    original_path: Option<String>,
}

/// The context is used to process incoming HTTP requests when the filter is not configured.
impl HttpContext for UnconfiguredOidc {

    /// This function is called when the request headers are received. As the filter is not
    /// configured, the request is paused and queued by the RootContext. Once the filter is
    /// configured, the request is resumed by the RootContext.
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        warn!("Filter not ready. Pausing request.");

        // Get the original path from the request headers
        self.original_path = Some(self.get_http_request_header(":path").unwrap_or("/".to_string()));

        Action::Pause
    }

    /// When the filter is configured, this function is called once the root context resumes the
    /// request. This function sends a redirect to create a new context for the configured filter.
    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {

        info!("Filter now ready. Sending redirect.");

        // Send a redirect to the original path
        self.send_http_response(302,
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

impl Context for UnconfiguredOidc {}

/// The ConfiguredOudc is the main filter struct and responsible for the OIDC authentication flow.
/// Requests arriving are checked for a valid cookie. If the cookie is valid, the request is
/// forwarded. If the cookie is not valid, the request is redirected to the OIDC provider.
struct ConfiguredOidc {
    /// The configuration of the filter which mainly contains the OIDC provider configuration and the
    /// keys to validate the JWT
    pub filter_config: Arc<OpenIdConfig>,
    /// Plugin configuration parsed from the envoy configuration
    pub plugin_config: Arc<PluginConfiguration>,
    /// Token id of the current request
    pub token_id: Option<u32>,
}

/// The context is used to process incoming HTTP requests when the filter is configured.
/// 1. Check if the request matches any of the exclude hosts, paths, urls. If so, forward the request.
/// 2. If the request is for the OIDC callback, dispatch the request to the token endpoint.
/// 3. If the request contains a cookie, validate the cookie and forward the request.
/// 4. Else, redirect the request to the OIDC provider.
impl HttpContext for ConfiguredOidc {

    /// This function is called when the request headers are received.
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {

        // Check if the host regex matches one of the exclude hosts. If so, forward the request.
        let host = self.get_http_request_header(":authority").unwrap_or_default();
        let host_regex = Regex::new(&host).unwrap();
        if self.plugin_config.exclude_hosts.iter().any(|x| host_regex.is_match(x)) {
            debug!("Host {} is excluded. Forwarding request.", host);
            return Action::Continue;
        }

        // If the path is one of the exclude paths, forward the request
        let path = self.get_http_request_header(":path").unwrap_or_default();
        let path_regex = Regex::new(&path).unwrap();
        if self.plugin_config.exclude_paths.iter().any(|x| path_regex.is_match(x)) {
            debug!("Path {} is excluded. Forwarding request.", path);
            return Action::Continue;
        }

        let url = Url::parse(&format!("{}{}", host, path)).unwrap();
        if self.plugin_config.exclude_urls.contains(&url.to_string()) {
            debug!("Url {} is excluded. Forwarding request.", url);
            return Action::Continue;
        }

        // If the request is for the OIDC callback, e.g the code is returned, this filter
        // exchanges the code for a token. The response is caught in on_http_call_response.
        if path.starts_with(Url::parse(&self.plugin_config.redirect_uri).unwrap().path()) {
            self.exchange_code_for_token(path).unwrap();
            return Action::Pause;
        }

        // If the requester passes a cookie, this filter passes the request depending on the validity of the cookie.
        if let Some(cookie) = self.get_cookie(&self.plugin_config.cookie_name) {
            match self.parse_and_validate_cookie(cookie) {
                Ok(_) => {
                    return Action::Continue;
                },
                Err(e) => {
                    warn!("Cookie validation failed: {}", e);
                }
            };
        }

        // Redirect to OIDC provider if no cookie is found. As all cases will have returned by now,
        // this is the last case and the request will be paused.
        self.redirect_to_authorization_endpoint();

        Action::Pause
    }
}

/// This context is used to process HTTP responses from the token endpoint.
impl Context for ConfiguredOidc {
    /// This function catches the response from the token endpoint.
    fn on_http_call_response(&mut self, token_id: u32, _: usize, body_size: usize, _: usize) {

        // Store the token in the cookie
        self.store_token_in_cookie(token_id, body_size);
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

    /// Parse the cookie and validate the token.
    /// The cookie is parsed into the `AuthorizationState` struct. The token is validated using the
    /// `validate_token` function. If the token is valid, this function returns Ok(()). If the token
    /// is invalid, this function returns Err(String) and redirects the requester to the OIDC provider.
    fn parse_and_validate_cookie(&self, cookie: String) -> Result<(), String> {

        debug!("Cookie found, checking validity.");

        // Try to parse the cookie and handle the result
        match cookie::AuthorizationState::parse_and_decode_cookie(cookie) {

            // If the cookie can be parsed, this filter validates the token
            Ok(auth_state) => {

                // Validate token
                match self.validate_token(&auth_state.id_token) {
                    // If the token is valid, this filter passes the request
                    Ok(_) => {
                        debug!("Token is valid, passing request.");
                        Ok(())
                    }
                    // If the token is invalid, this filter redirects the requester to the OIDC provider
                    Err(_) => {

                        Err("Token is invalid.".to_string())
                    }
                }
            }
            // If the cookie cannot be parsed, this filter redirects the requester to the OIDC provider
            Err(err) => {
                self.redirect_to_authorization_endpoint();
                return Err(format!("Authorisation state couldn't be loaded from the cookie: {:?}",err));
            }
        }
    }


    /// Validate the token using the JWT library.
    /// This function checks for the correct issuer and audience and verifies the signature with the
    /// public keys loaded from the JWKs endpoint.
    fn validate_token(&self, token: &str) -> Result<(), String> {

        // Define allowed issuers and audiences
        let mut allowed_issuers = HashSet::new();
        allowed_issuers.insert(self.filter_config.issuer.to_string());
        let mut allowed_audiences = HashSet::new();
        allowed_audiences.insert(self.plugin_config.audience.to_string());

        // Define verification options
        let verification_options = VerificationOptions {
            allowed_issuers: Some(allowed_issuers),
            allowed_audiences: Some(allowed_audiences),

            reject_before: None,
            accept_future: false,
            required_subject: None,
            required_key_id: None,
            required_public_key: None,
            required_nonce: None,
            time_tolerance: None,
            max_validity: None,
            max_header_length: None,
            max_token_length: None,
        };

        // Iterate over all public keys
        for public_key in &self.filter_config.public_keys {

            // Perform the validation
            let validation_result =
                public_key.verify_token::<NoCustomClaims>(&token, Some(verification_options.to_owned()));

            // Check if the token is valid, the aud and iss are correct and the signature is valid.
            match validation_result {
                Ok(_) => {
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
    /// This function is called when the OIDC provider redirects back to the callback URL.
    /// The code is extracted from the URL and exchanged for a token using the token endpoint.
    fn exchange_code_for_token(&mut self, path: String) -> Result<(), String>{

        debug!("Received request for OIDC callback.");

        // Extract code from the url
        let code = path.split("=").last().unwrap_or_default();
        debug!("Code: {}", code);

        // Hardcoded values for request to token endpoint
        let client_id = &self.plugin_config.client_id;
        let client_secret = &self.plugin_config.client_secret;

        // Encode client_id and client_secret and build the Authorization header using base64encoding
        let encoded = base64engine.encode(format!("{client_id}:{client_secret}").as_bytes());
        let auth = format!("Basic {}", encoded);

        // Get code verifier from cookie
        let code_verifier = self.get_cookie("pkce-verifier").unwrap_or_default();

        // Build the request body for the token endpoint
        let data: String = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code_verifier", &code_verifier)
            .append_pair("code", &code)
            .append_pair("redirect_uri", self.plugin_config.redirect_uri.as_str())
            // TODO: Nonce #7
            .finish();

        // Get path from token endpoint
        let token_endpoint = self.filter_config.token_endpoint.path();

        // Dispatch request to token endpoint using built-in envoy function
        debug!("Sending data to token endpoint: {}", data);
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
               return Err(format!("Failed to dispatch HTTP request: {:?}", err));
            }
        }
    }

    /// Store the token from the token response in a cookie.
    /// Parse the token with the `AuthorizationState` struct and store it in an encoded cookie.
    /// Then, redirect the requester to the original URL.
    fn store_token_in_cookie(&mut self, token_id: u32, body_size: usize) {
        // Assess token id
        if self.token_id != Some(token_id) {
            warn!("Token id does not match.");
            return;
        }

        // Check if the response is valid. If its not 200, investigate the response
        // and log the error.
        if self.get_http_call_response_header(":status") != Some("200".to_string()) {

            // Get body of response
            if let Some(body) = self.get_http_call_response_body(0, body_size) {

                // Decode body
                if let Ok(decoded) = String::from_utf8(body) {
                    warn!("Token response is not valid: {:?}", decoded);
                    return;

                // If decoding fails, log the error
                } else {
                    warn!("Token response is not valid and error decoding error message.");
                    return;
                }

            // If no body is found, log the error
            } else {
                warn!("No body in token response with invalid status code.");
                return;
            }
        }

        // Catching token response from token endpoint. Previously we checked for the status code and
        // the body, so we can assume that the response is valid.
        if let Some(body) = self.get_http_call_response_body(0, body_size) {
            debug!("Token response: {:?}", body);

            // Build Cookie Struct using parse_response from cookie.rs
            match cookie::AuthorizationState::create_cookie_from_response(body.as_slice()) {
                Ok(auth_cookie) => {
                    debug!("Cookie: {:?}", &auth_cookie);

                    // Get Source cookie
                    let original_path = self.get_cookie("original-path");

                    // Redirect back to the original URL and set the cookie.
                    self.send_http_response(
                        302,
                        vec![
                            // Set the cookie
                            ("Set-Cookie", &format!("{}={}; Path=/; Max-Age={}",
                                &self.plugin_config.cookie_name,
                                &auth_cookie,
                                &self.plugin_config.cookie_duration)),
                            // Redirect to source
                            ("Location",
                                &original_path.unwrap_or("/".to_owned())),
                        ],
                        Some(b"Redirecting..."),
                    );
                }
                Err(e) => {
                    warn!("Error: {}", e);
                }
            }
        // If no body is found, log the error
        } else {
            warn!("No body found in token response with valid status code.");
        }
    }

    /// Redirect to the OIDC provider by sending a HTTP response with a 302 status code.
    fn redirect_to_authorization_endpoint(&self) -> Action {

        // Original path
        let original_path = self.get_http_request_header(":path").unwrap_or_default();

        debug!("No cookie found or invalid, redirecting to OIDC provider.");
                // Generate PKCE code verifier and challenge
        let pkce_verifier = pkce::code_verifier(128);
        let pkce_verifier_string = String::from_utf8(pkce_verifier.clone()).unwrap();
        let pkce_challenge = pkce::code_challenge(&pkce_verifier);

        // Build URL
        let url = Url::parse_with_params(
            self.filter_config.auth_endpoint.as_str(),
            &[
                ("response_type", "code"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
                ("client_id", &self.plugin_config.client_id),
                ("redirect_uri",&self.plugin_config.redirect_uri.as_str()),
                ("scope", &self.plugin_config.scope),
                ("claims", &self.plugin_config.claims),
            ],
        )
        .unwrap();

        // Send HTTP response
        self.send_http_response(
            302,
            vec![
                // Original path
                ("Set-Cookie", &format!("original-path={}", &original_path)),
                // Set the pkce challenge as a cookie to verify the callback.
                ("Set-Cookie", &format!("pkce-verifier={}; Max-Age={}", &pkce_verifier_string, 60)),
                // Redirect to OIDC provider
                ("Location", url.as_str()),
                ],
                Some(b"Redirecting..."),
            );
            return Action::Pause;
    }
}
