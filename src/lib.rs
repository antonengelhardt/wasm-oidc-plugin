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
use log::info;

// base64
use base64::{engine::general_purpose, Engine as _};

// jsonwebtoken
// use jsonwebtoken::{decode, DecodingKey, Validation};

// dotenv
// use dotenv::dotenv;

// duration
use std::time::Duration;

// proxy-wasm
use proxy_wasm::hostcalls::*;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// serde
use serde::Deserialize;

// url
use url::{form_urlencoded, Url};

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_http_context(|_, _| -> Box<dyn HttpContext> { Box::new(OIDCFlow) });
}}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    error: String,
    // #[serde(default)]
    // error_description: String,
    #[serde(default)]
    id_token: String,
    // #[serde(default)]
    // expires_in: i64,
}

struct OIDCFlow;

struct OIDCFlowRootContext {}

impl OIDCFlow {
    // Validate the token using the JWT library.
    fn validate_token(&self, _token: &str) -> Result<(), String> {
        let _issuer_url = "https://auth.k8s.wwu.de";
        // TODO: Validate the token using the JWT library
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

    fn _get_header(&self, name: &str) -> String {
        let headers = self.get_http_request_headers();
        for (key, _value) in headers.iter() {
            if key.to_lowercase().trim() == name {
                return _value.to_owned();
            }
        }
        return "".to_owned();
    }

    fn get_cookie(&self, name: &str) -> String {
        let headers = self.get_http_request_headers();
        for (key, value) in headers.iter() {
            if key.to_lowercase().trim() == "cookie" {
                let cookies: Vec<_> = value.split(";").collect();
                for cookie_string in cookies {
                    let cookie_name_end = cookie_string.find('=').unwrap_or(0);
                    let cookie_name = &cookie_string[0..cookie_name_end];
                    if cookie_name.trim() == name {
                        return cookie_string[(cookie_name_end + 1)..cookie_string.len()]
                            .to_owned();
                    }
                }
            }
        }
        return "".to_owned();
    }

    // Build the Set-Cookie header to set the token in the browser.
    fn to_set_cookie_header(&self, t: TokenResponse) -> String {
        return format!("{}={}", "id-token", t.id_token);
    }
}

impl HttpContext for OIDCFlow {
    // This function is called when the request headers are received.
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {

        // If the requester passes a cookie, this filter sets the header and passes the request
        let token = self.get_cookie("id-token");
        if token != "" {
            info!("Cookie found, passing request");

            self.resume_http_request();
            return Action::Continue;
        }

        // If the request is for the OIDC callback, continue the request.
        let path = self.get_http_request_header(":path").unwrap_or_default();
        if path.starts_with("/oidc/callback") {

            // Extract code
            let code = path.split("=").last().unwrap_or_default();
            info!("Code: {}", code);

            let client_id = "wasm-oidc-plugin";

            // dotenv().unwrap();
            //let client_secret = std::env::var("CLIENT_SECRET").unwrap();
            let client_secret = "redacted";
            let encoded = general_purpose::STANDARD_NO_PAD
                .encode(format!("{}:{}", client_id, client_secret).as_bytes());
            let auth = format!("Basic {}", encoded);
            let redirect_uri = "http://localhost:10000/oidc/callback";

            let data: String = form_urlencoded::Serializer::new(String::new())
                .append_pair("code", &code)
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("grant_type", "authorization_code")
                // .append_pair("nonce", handshake.nonce.as_str())
                .finish();

            info!("Sending data to token endpoint: {}", data);
            let token_request = dispatch_http_call(
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
                Duration::from_secs(5),
            );

            match token_request {
                Ok(_) => {
                    info!("Token request dispatched successfully.");
                }
                Err(err) => info!("Token request failed: {:?}", err),
            }
            return Action::Pause;
        }

        // Redirect to OIDC provider if no token is found
        info!("No cookie found, redirecting to OIDC provider.");
        self.send_http_response(
            302,
            vec![
                ("Set-Cookie", &format!("source={}", path)),
                ("Location", &OIDCFlow.redirect_to_oidc()),
                // Set the source url as a cookie to redirect back to it after the callback.
            ],
            Some(b"Redirecting..."),
        );
        return Action::Pause;
    }
}

impl Context for OIDCFlow {
    fn on_http_call_response(&mut self, _: u32, _: usize, body_size: usize, _: usize) {
        // Catching token response
        info!("Token response received.");
        if let Some(body) = self.get_http_call_response_body(0, body_size) {
            match serde_json::from_slice::<TokenResponse>(body.as_slice()) {
                Ok(data) => {
                    // Check for errors.
                    if data.error != "" {
                        info!("Error: {}", data.error);
                        return;
                    }

                    // Check for source cookie
                    let source = self.get_cookie("source");
                    if source != "" {
                        info!("Source: {}", source);
                    }

                    // Check for ID token.
                    if data.id_token != "" {
                        info!("ID Token: {}", data.id_token);

                        // TODO: Login server vertrauen und evtl. hier nicht validieren
                        // Validate the token.
                        match OIDCFlow.validate_token(&data.id_token) {
                            Ok(_) => info!("Token is valid."),
                            Err(err) => {
                                info!("Token is invalid: {}", err);
                                return;
                            }
                        }

                        // TODO: Redirect to the original URL.
                        self.get_http_request_header("source").unwrap_or_default();

                        // let source_url = format!("http://localhost:10000{}", source);

                        self.send_http_response(
                            302,
                            vec![
                                ("Set-Cookie", self.to_set_cookie_header(data).as_str()),
                                //TODO: This results in a loop.
                                // ("Location", "http://localhost:10000/"),
                                ("Location", "/")
                                // ("id_token", &data.id_token),
                                // ("Location", &source_url),
                            ],
                            Some(b"Redirecting..."),
                        );

                        // self.resume_http_request();
                        return;
                    }
                }
                Err(e) => {
                    info!("Invalid Token Reponse: {}", e);
                    return;
                }
            }
        } else {
            info!("No body found. Cannot parse token response.");
            return;
        }
    }
}

impl Context for OIDCFlowRootContext {}

impl RootContext for OIDCFlowRootContext {
    fn on_configure(&mut self, _: usize) -> bool {
        info!("on_configure");
        true
    }

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(OIDCFlow))
    }
}
