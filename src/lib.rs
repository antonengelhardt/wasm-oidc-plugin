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
use log::debug;

// base64
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as base64engine, engine::general_purpose::URL_SAFE_NO_PAD as base64engine_urlsafe};
use log::info;
use serde::de::Error;

// duration
use std::time::Duration;
use std::time::SystemTime;

// proxy-wasm
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// serde
// use serde::{Deserialize};

// jwt
use jwt_simple::prelude::*;
use jwt_simple::claims::*;
use jwt_simple::algorithms;

// url
use url::{form_urlencoded, Url};

mod cookie;
use cookie::AuthorizationState;

mod config;
use config::FilterConfig;

proxy_wasm::main! {{

    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_http_context(|_, _| -> Box<dyn HttpContext> { Box::new(OIDCFlow{


        config: FilterConfig {
            // TODO: Get OpenID Connect configuration #3
            cookie_name: "oidcSession".to_owned(),

            // Relevant for the Authorization Code Flow
            auth_endpoint: Url::parse("https://auth.k8s.wwu.de/saml2/oidc/authorization").unwrap(),
            redirect_uri: Url::parse("http://localhost:10000/oidc/callback").unwrap(),
            response_type: "code".to_owned(),
            client_id: "wasm-oidc-plugin".to_owned(),
            scope: "openid email".to_owned(),
            claims: r#"{"id_token":{"username":null,"groups":null}}"#.to_owned(),

            // Relevant for the Token Endpoint
            token_endpoint: Url::parse("https://auth.k8s.wwu.de/oidc/token").unwrap(),
            grant_type: "authorization_code".to_owned(),
            client_secret: "redacted".to_owned(),
            audience: "wasm-oidc-plugin".to_owned(),
            issuer: "https://auth.k8s.wwu.de".to_owned(),

            // Relevant for id_token validation
        }
     })});
}}

struct OIDCFlow {
    config: FilterConfig,
}

impl OIDCFlow {
    // Validate the token using the JWT library.
    fn validate_token(&self, token: &str) -> Result<(), String> {

        // TODO: Check for aud (audience) and iss (issuer) #5

        // Extract aud (audience) and iss (issuer) from the token
        let token_parts = token.split('.').collect::<Vec<&str>>();
        let token_data = token_parts[1];

        // Decode and parse the token data
        let token_data_decoded = base64engine.decode(token_data).unwrap();
        let token_data_parsed = serde_json::from_slice::<serde_json::Value>(&token_data_decoded).unwrap();

        // Extract aud and iss from the token data
        let aud = token_data_parsed["aud"].as_str().unwrap();
        let iss = token_data_parsed["iss"].as_str().unwrap();

        match aud == self.config.audience.as_str() && iss == self.config.issuer.as_str() {
            true => {
                info!("Audience and issuer are valid");
            }
            false => {
                info!("Audience and issuer are invalid");
                return Err("Audience and issuer are invalid".into());
            }
        }

        // TODO: Check for exp (expiration time)

        // TODO: Validate the token using the JWT library #5

        Ok(())

    }

    // Build the URL to redirect to the OIDC provider along with the required parameters.
    fn redirect_to_oidc(&self) -> String {

        // Build URL
        let url = Url::parse_with_params(
            &self.config.auth_endpoint.as_str(),
            &[
                ("redirect_uri", self.config.redirect_uri.as_str()),
                ("response_type", self.config.response_type.as_str()),
                ("client_id", &self.config.client_id),
                ("scope", &self.config.scope),
                ("claims", &self.config.claims),
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
    fn set_state_cookie(&self, auth_state: &AuthorizationState) -> String {
        // TODO: HTTP Only, Secure, Max-Age
        return format!("{}={}; Path=/",
            self.config.cookie_name,
            serde_json::to_string(auth_state).unwrap());
    }
}

impl HttpContext for OIDCFlow {
    // This function is called when the request headers are received.
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {

        // If the requester passes a cookie, this filter passes the request
        if let Some(auth_cookie) = self.get_cookie(&self.config.cookie_name) {
            debug!("Cookie found, passing request");

            // Decode cookie
            let auth_state = cookie::AuthorizationState::parse_cookie(auth_cookie).unwrap();

            // Validate token
            let validation_result = self.validate_token(&auth_state.id_token);
            match validation_result {
                Ok(_) => {
                    debug!("Token is valid");
                    return Action::Continue;
                }
                Err(_) => {
                    debug!("Token is invalid");
                    return Action::Pause;
                }
            }
        }


        // If the request is for the OIDC callback, e.g the code is returned, this filter
        // exchanges the code for a token. The response is caught in on_http_call_response.
        let path = self.get_http_request_header(":path").unwrap_or_default();
        if path.starts_with("/oidc/callback") {
            // Extract code from the url
            let code = path.split("=").last().unwrap_or_default();
            debug!("Code: {}", code);

            // Hardcoded values for request to token endpoint
            let client_id = &self.config.client_id;
            let client_secret = &self.config.client_secret;

            // Encode client_id and client_secret and build the Authorization header
            let encoded = base64engine
                .encode(format!("{client_id}:{client_secret}").as_bytes());
            let auth = format!("Basic {}", encoded);

            // Build the request body
            let data: String = form_urlencoded::Serializer::new(String::new())
                .append_pair("code", &code)
                .append_pair("redirect_uri", &self.config.redirect_uri.as_str())
                .append_pair("grant_type", &self.config.grant_type.as_str())
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
                ("Set-Cookie", &format!("source={}", path)),
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
            // Build Cookie Struct using parse_response from cookie.rs
            match cookie::AuthorizationState::parse_response(body.as_slice()) {
                Ok(auth_cookie) => {
                    debug!("Cookie: {:?}", &auth_cookie);

                    // Get Source cookie
                    let source_cookie = self.get_cookie("source");

                    // Redirect back to the original URL.
                    self.send_http_response(
                        302,
                        vec![
                            // TODO: Encode cookie #2
                            ("Set-Cookie", self.set_state_cookie(&auth_cookie).as_str()),
                            ("Location", &source_cookie.unwrap_or("/".to_owned())),
                        ],
                        Some(b"Redirecting..."),
                    );
                }
                Err(e) => {
                    debug!("Error: {}", e);
                }
            }
        } else {
            debug!("No body found.");
        }
    }
}
