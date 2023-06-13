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
use log::{debug,warn};

// base64
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64engine, Engine as _};

// duration
use std::time::Duration;

// arc
use std::sync::Arc;

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
use config::FilterConfig;

mod discovery;

/// The OIDCFlow is the main filter struct and responsible for the OIDC authentication flow.
struct OIDCFlow {
    /// The configuration of the filter which is loaded from the plugin config & discovery endpoints.
    config: Arc<FilterConfig>,
}

/// The context is used to process incoming HTTP requests.
impl HttpContext for OIDCFlow {

    /// This function is called when the request headers are received.
    /// If the request is for the OIDC callback, the request is dispatched to the token endpoint.
    /// If the request is not for the OIDC callback and contains a cookie, the cookie is validated
    /// and the request is forwarded.
    /// Else, the request is redirected to the OIDC provider.
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {

        // If the request is for the OIDC callback, e.g the code is returned, this filter
        // exchanges the code for a token. The response is caught in on_http_call_response.
        let path = self.get_http_request_header(":path").unwrap_or_default();
        if path.starts_with(&self.config.call_back_path) {
            debug!("Received request for OIDC callback.");

            // Extract code from the url
            let code = path.split("=").last().unwrap_or_default();
            debug!("Code: {}", code);

            // Hardcoded values for request to token endpoint
            let client_id = &self.config.client_id;
            let client_secret = &self.config.client_secret;

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
                .append_pair("redirect_uri", &self.config.redirect_uri.as_str())
                // TODO: Nonce #7
                .finish();

            // Dispatch request to token endpoint using built-in envoy function
            debug!("Sending data to token endpoint: {}", data);
            match self.dispatch_http_call(
                "oidc",
                vec![
                    (":method", "POST"),
                    (":path", "/oidc/token"),
                    (":authority", &self.config.authority),
                    ("Authorization", &auth),
                    ("Content-Type", "application/x-www-form-urlencoded"),
                ],
                Some(data.as_bytes()),
                vec![],
                Duration::from_secs(10),
             ) {
                // If the request is dispatched successfully, this filter pauses the request
                Ok(_) => {
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
        if let Some(auth_cookie) = self.get_cookie(&self.config.cookie_name) {
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
impl Context for OIDCFlow {
    /// This function catches the response from the token endpoint.
    fn on_http_call_response(&mut self, _: u32, _: usize, body_size: usize, _: usize) {

        // Check if the response is valid
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
impl OIDCFlow {
    /// Validate the token using the JWT library.
    /// This function checks for the correct issuer and audience and verifies the signature.
    fn validate_token(&self, token: &str) -> Result<(), String> {
        // Get public key from the config
        let public_key = &self.config.public_key;

        // Define allowed issuers and audiences
        let mut allowed_issuers = HashSet::new();
        allowed_issuers.insert(self.config.issuer.to_string());
        let mut allowed_audiences = HashSet::new();
        allowed_audiences.insert(self.config.audience.to_string());

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

        // Perform the validation
        let validation_result =
            public_key.verify_token::<NoCustomClaims>(&token, Some(verification_options));

        // Check if the token is valid, the aud and iss are correct and the signature is valid.
        match validation_result {
            Ok(_) => {
                return Ok(());
            }
            Err(e) => {
                return Err(e.to_string());
            }
        }
    }

    /// Build the URL to redirect to the OIDC provider along with the required parameters.
    fn build_authorization_url(&self, code_challenge: String) -> String {
        // Build URL
        let url = Url::parse_with_params(
            &self.config.auth_endpoint.as_str(),
            &[
                ("response_type", "code"),
                ("code_challenge", &code_challenge),
                ("code_challenge_method", "S256"),
                ("client_id", &self.config.client_id),
                ("redirect_uri", self.config.redirect_uri.as_str()),
                ("scope", &self.config.scope),
                ("claims", &self.config.claims),
            ],
        )
        .unwrap();

        return url.to_string();
    }

    /// Send 302 redirect to the OIDC provider.
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
            self.config.cookie_name,
            serde_json::to_string(auth_state).unwrap(),
            self.config.cookie_duration,
        );
    }
}
