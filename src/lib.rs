// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

mod cookie;
use cookie::AuthorizationState;

mod config;
use config::{OpenIdConfig, PluginConfiguration};

mod discovery;

mod responses;

/// The UnconfiguredOidc is the filter struct which is used when the filter is not configured.
struct UnconfiguredOidc;

/// The context is used to process incoming HTTP requests when the filter is not configured.
impl HttpContext for UnconfiguredOidc {

    /// This function is called when the request headers are received. As the filter is not
    /// configured, the request is paused and queued by the RootContext. Once the filter is
    /// configured, the request is resumed by the RootContext.
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        warn!("Filter not ready. Pausing request.");

        Action::Pause
    }

    /// When the filter is configured, this function is called once the root context resumes the
    /// request. This function sends a redirect to create a new context for the configured filter.
    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {

        info!("Filter now ready. Sending redirect.");

        self.send_http_response(302,
            vec![
            // Redirect to the requested path
            ("location", "/"),
            // Disable caching
            ("Cache-Control", "no-cache"),
        ],
        Some(b"Filter is ready now."));
        Action::Continue
    }
}

impl Context for UnconfiguredOidc {}

/// The ConfiguredOudc is the main filter struct and responsible for the OIDC authentication flow.
struct ConfiguredOidc {
    /// The configuration of the filter which is loaded from the plugin config & discovery endpoints.
    pub filter_config: Arc<OpenIdConfig>,
    /// Plugin configuration
    pub plugin_config: Arc<PluginConfiguration>,
    /// Token id of the current request
    pub token_id: Option<u32>,
}

/// The context is used to process incoming HTTP requests when the filter is configured.
impl HttpContext for ConfiguredOidc {

    /// This function is called when the request headers are received.
    /// If the request is for the OIDC callback, the request is dispatched to the token endpoint.
    /// If the request is not for the OIDC callback and contains a cookie, the cookie is validated
    /// and the request is forwarded.
    /// Else, the request is redirected to the OIDC provider.
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {

        // Get the path of the request
        let host = self.get_http_request_header(":authority").unwrap_or_default();
        let path = self.get_http_request_header(":path").unwrap_or_default();
        let url = format!("{}{}", host, path);

        if self.plugin_config.exclude_hosts.contains(&host) {
            debug!("Host {} is excluded. Forwarding request.", host);
            return Action::Continue;
        }

        // If the path is one of the exclude paths, forward the request
        if self.plugin_config.exclude_urls.contains(&url) {
            debug!("Path {} is excluded. Forwarding request.", url);
            return Action::Continue;
        }

        // If the request is for the OIDC callback, e.g the code is returned, this filter
        // exchanges the code for a token. The response is caught in on_http_call_response.
        if path.starts_with(Url::parse(&self.plugin_config.redirect_uri).unwrap().path()) {
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
            let code_verifier = self.get_cookie("pkce").unwrap_or_default();

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
                    debug!("Token request dispatched successfully.");
                }
                // If the request fails, this filter logs the error and pauses the request
                Err(err) => {
                    warn!("Token request failed: {:?}", err);
                }
            }
            return Action::Pause;
        }

        // If the requester passes a cookie, this filter passes the request depending on the validity of the cookie.
        if let Some(auth_cookie) = self.get_cookie(&self.plugin_config.cookie_name) {
            debug!("Cookie found, checking validity.");

            // Try to parse the cookie and handle the result
            match cookie::AuthorizationState::parse_cookie(auth_cookie) {

                // If the cookie can be parsed, this filter validates the token
                Ok(auth_state) => {

                    // Validate token
                    match self.validate_token(&auth_state.id_token) {
                        // If the token is valid, this filter passes the request
                        Ok(_) => {
                            debug!("Token is valid, passing request.");
                            return Action::Continue;
                        }
                        // If the token is invalid, this filter redirects the requester to the OIDC provider
                        Err(_) => {
                            warn!("Token is invalid, redirecting to OIDC provider.");

                            self.redirect_to_authorization_endpoint();
                        }
                    }
                }
                // If the cookie cannot be parsed, this filter redirects the requester to the OIDC provider
                Err(err) => {
                    warn!("Authorisation state couldn't be loaded from the cookie: {:?}",err);
                }
            }
        }

        // Redirect to OIDC provider if no cookie is found. As all cases will have returned by now,
        // this is the last case and the request will be paused.
        debug!("No cookie found, redirecting to OIDC provider.");

        self.redirect_to_authorization_endpoint();

        return Action::Pause;
    }
}

/// This context is used to process HTTP responses from the token endpoint.
impl Context for ConfiguredOidc {
    /// This function catches the response from the token endpoint.
    fn on_http_call_response(&mut self, token_id: u32, _: usize, body_size: usize, _: usize) {

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
                    let source_cookie = self.get_cookie("source");

                    // Redirect back to the original URL.
                    self.send_http_response(
                        302,
                        vec![
                            // TODO: Encode cookie #2
                            // Set the cookie
                            ("Set-Cookie", self.set_state_cookie(&auth_cookie).as_str()),
                            // Redirect to source
                            ("Location", &source_cookie.unwrap_or("/".to_owned())),
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
}

/// Helper functions for the OIDCFlow struct.
impl ConfiguredOidc {
    /// Validate the token using the JWT library.
    /// This function checks for the correct issuer and audience and verifies the signature.
    fn validate_token(&self, token: &str) -> Result<(), String> {

        // Define allowed issuers and audiences
        let mut allowed_issuers = HashSet::new();
        allowed_issuers.insert(self.filter_config.issuer.to_string());
        let mut allowed_audiences = HashSet::new();
        allowed_audiences.insert(self.plugin_config.audience.to_string());

        // Verify the token
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

    /// Redirect to the OIDC provider.
    fn redirect_to_authorization_endpoint(&self) {

        // Generate PKCE code verifier and challenge
        let pkce_verifier = pkce::code_verifier(128);
        let pkce_verifier_string = String::from_utf8(pkce_verifier.clone()).unwrap();
        let pkce_challenge = pkce::code_challenge(&pkce_verifier);

        self.send_http_response(
            302,
            vec![
                // Set the pkce challenge as a cookie to verify the callback.
                ("Set-Cookie", &format!("pkce={}", &pkce_verifier_string)),
                // Redirect to OIDC provider
                ("Location", self.build_authorization_url(pkce_challenge).as_str()),
                ],
                Some(b"Redirecting..."),
            );
        }

    /// Build the URL to redirect to the OIDC provider along with the required parameters.
    fn build_authorization_url(&self, code_challenge: String) -> String {

        // Build URL
        let url = Url::parse_with_params(
            self.filter_config.auth_endpoint.as_str(),
            &[
                ("response_type", "code"),
                ("code_challenge", &code_challenge),
                ("code_challenge_method", "S256"),
                ("client_id", &self.plugin_config.client_id),
                ("redirect_uri",&self.plugin_config.redirect_uri.as_str()),
                ("scope", &self.plugin_config.scope),
                ("claims", &self.plugin_config.claims),
            ],
        )
        .unwrap();

        return url.to_string();
    }

    /// Get the cookie of the HTTP request by name
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

    /// Build the Cookie content to set the cookie in the HTTP response.
    fn set_state_cookie(&self, auth_state: &AuthorizationState) -> String {
        // TODO: HTTP Only, Secure
        return format!(
            "{}={}; Path=/; Max-Age={}",
            &self.plugin_config.cookie_name,
            serde_json::to_string(auth_state).unwrap(),
            &self.plugin_config.cookie_duration,
        );
    }
}
