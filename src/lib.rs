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

use cookie::AuthorizationState;

// log
use log::info;
use log::debug;

// base64
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as base64encoder};

// duration
use std::time::Duration;

// proxy-wasm
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// serde
// use serde::{Deserialize};

// url
use url::{form_urlencoded, Url};

mod cookie;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_http_context(|_, _| -> Box<dyn HttpContext> { Box::new(OIDCFlow) });
}}

struct OIDCFlow;

struct OIDCFlowRootContext {}

impl OIDCFlow {
    // Validate the token using the JWT library.
    fn validate_token(&self, _token: &str) -> Result<(), String> {
        let _issuer_url = "https://auth.k8s.wwu.de";
        let _audience = "wasm-oidc-plugin";

        // TODO: Validate the token using the JWT library, check for signature. #5
        // TODO: Check for aud (audience) and iss (issuer) #5

        Ok(())
    }

    // Build the URL to redirect to the OIDC provider along with the required parameters.
    fn redirect_to_oidc(&self) -> String {
        let auth_endpoint = "https://auth.k8s.wwu.de/saml2/oidc/authorization";
        let redirect_uri = "http://localhost:10000/oidc/callback";
        let response_type = "code";
        let client_id = "wasm-oidc-plugin";
        let scope = "openid account";
        let claims = r#"{"id_token":{"username":null,"groups":null}}"#;

        let url = Url::parse_with_params(
            auth_endpoint,
            &[
                ("redirect_uri", redirect_uri),
                ("response_type", response_type),
                ("client_id", client_id),
                ("scope", scope),
                ("claims", claims),
            ],
        )
        .unwrap();

        return url.to_string();
    }

    // Get the header of the HTTP request
    fn _get_header(&self, name: &str) -> Option<String> {
        let headers = self.get_http_request_headers();
        for (key, value) in headers.iter() {
            if key.to_lowercase().trim() == name {
                return Some(value.to_owned());
            }
        }
        return None;
    }

    // Get the cookie of the HTTP request
    fn get_cookie(&self, name: &str) -> Option<String> {
        let headers = self.get_http_request_headers();
        for (key, value) in headers.iter() {
            if key.to_lowercase().trim() == "cookie" {
                let cookies: Vec<_> = value.split(";").collect();
                for cookie_string in cookies {
                    let cookie_name_end = cookie_string.find('=').unwrap_or(0);
                    let cookie_name = &cookie_string[0..cookie_name_end];
                    if cookie_name.trim() == name {
                        return Some(cookie_string[(cookie_name_end + 1)..cookie_string.len()]
                            .to_owned());
                    }
                }
            }
        }
        return None
    }

    // Build the Set-Cookie header to set the token in the browser.
    fn set_state_cookie(&self, a: &AuthorizationState) -> String {
        // TODO: HTTP Only, Secure, Max-Age
        return format!("auth={}; Path=/", serde_json::to_string(a).unwrap());
    }
}

impl HttpContext for OIDCFlow {
    // This function is called when the request headers are received.
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        // If the requester passes a cookie, this filter passes the request
        let token = self.get_cookie("id-token");
        if token != None {
            debug!("Cookie found, passing request");

            // Decode cookie
            let auth_state = cookie::AuthorizationState::parse_cookie(auth_cookie).unwrap();

            return Action::Continue;
        }

        // If the request is for the OIDC callback, e.g the code is returned, this filter
        // exchanges the code for a token. The response is caught in on_http_call_response.
        let path = self.get_http_request_header(":path").unwrap_or_default();
        if path.starts_with("/oidc/callback") {
            // Extract code from the url
            let code = path.split("=").last().unwrap_or_default();
            debug!("Code: {}", code);

            // TODO: Make Configurable #3

            // Hardcoded values for request to token endpoint
            let client_id = "wasm-oidc-plugin";
            let client_secret = "redacted";
            let redirect_uri = "http://localhost:10000/oidc/callback"; // Fixed

            // Encode client_id and client_secret and build the Authorization header
            let encoded = base64encoder
                .encode(format!("{client_id}:{client_secret}").as_bytes());
            let auth = format!("Basic {}", encoded);

            // Build the request body
            let data: String = form_urlencoded::Serializer::new(String::new())
                .append_pair("code", &code)
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("grant_type", "authorization_code")
                // TODO: PKCE #6
                // TODO: Nonce #7
                .finish();

            // Dispatch request to token endpoint
            debug!("Sending data to token endpoint: {}", data);
            let token_request = self.dispatch_http_call(
                "oidc",
                vec![
                    (":method", "POST"),
                    (":path", "/oidc/token"),
                    (":authority", "auth.k8s.wwu.de"),
                    ("Authorization", &auth),
                    ("Content-Type", "application/x-www-form-urlencoded"),
                ],
                Some(data.as_bytes()),
                vec![],
                Duration::from_secs(10),
            );

            // Check if the request was dispatched successfully
            match token_request {
                Ok(_) => {
                    debug!("Token request dispatched successfully.");
                }
                Err(err) => debug!("Token request failed: {:?}", err),
            }
            return Action::Pause;
        }

        // Redirect to OIDC provider if no cookie is found
        debug!("No cookie found, redirecting to OIDC provider.");
        self.send_http_response(
            302,
            vec![
                // Set the source url as a cookie to redirect back to it after the callback.
                // ("Set-Cookie", &format!("source={}", path)),
                // Redirect to OIDC provider
                ("Location", self.redirect_to_oidc().as_str()),
            ],
            Some(b"Redirecting..."),
        );
        return Action::Pause;
    }
}

impl Context for OIDCFlow {
    // This function is called when the response headers are received.
    fn on_http_call_response(&mut self, _: u32, _: usize, body_size: usize, _: usize) {
        // Catching token response
        debug!("Token response received.");
        if let Some(body) = self.get_http_call_response_body(0, body_size) {

            // Build Cookie using parse_response from cookie.rs
            let auth_cookie = cookie::AuthorizationState::parse_response(body).unwrap();

            // Redirect back to the original URL.
            self.send_http_response(
                302,
                vec![
                    // TODO: Encode cookie #2
                    ("Set-Cookie", self.set_state_cookie(&auth_cookie).as_str()),
                    ("Location", "/"),
                    ],
                Some(b"Redirecting..."),
            );
        }
    }
}

impl Context for OIDCFlowRootContext {}

impl RootContext for OIDCFlowRootContext {
    // This function is called when the VM is initialized.
    fn on_configure(&mut self, _: usize) -> bool {
        debug!("on_configure");
        true
        // TODO: Get OpenID Connect configuration #3
    }

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(OIDCFlow))
    }
}
