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

// proxy-wasm
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// url
use url::Url;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_http_context(|_, _| -> Box<dyn HttpContext> { Box::new(OIDCFlow) });
}}

struct HttpAuth;

impl HttpAuth {

    // Validate the token using the JWT library.
    fn validate_token(&self, _token: &str) -> Result<(), String> {
        let _issuer_url = "https://auth.k8s.wwu.de";
        // TODO: Validate the token using the JWT library.
        // let validation = Validation::default();
        // let decoded = decode::<Value>(token, &DecodingKey::from_secret("secret".as_ref()), &validation);

        // match decoded {
            //     Ok(_) => Ok(()),
            //     Err(err) => return Err(err.to_string()),
            // }
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
}

struct OIDCFlow;

impl HttpContext for OIDCFlow {
    // This function is called when the request headers are received.
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        let path = self.get_http_request_header(":path").unwrap_or_default();
        let headers = self.get_http_request_headers();
        // TODO: The header name is most likely not "Authorization".
        let token_header = headers.iter().find(|(name, _)| name == "Authorization");

        // If the request is for the OIDC callback, continue the request.
        if path.starts_with("/oidc/callback") {
            info!("Access granted.");
            // Extract code
            let code = path.split("=").last().unwrap_or_default();
            info!("Code: {}", code);
            self.resume_http_request();
            return Action::Continue;
        }

        // If the request is not for the OIDC callback, check for an existing token.
        match token_header {
            // If the token is found, validate it.
            // TODO: Validate the token.
            Some((_, token)) => match HttpAuth.validate_token(token) {
                // If the token is valid, continue the request.
                Ok(_) => {
                    info!("Access granted.");
                    self.resume_http_request();
                    return Action::Continue;
                }

                // If the token is invalid, redirect to OIDC provider.
                Err(err) => {
                    info!("Access denied: {}", err);
                    self.send_http_response(
                        401,
                        vec![("location", &HttpAuth.redirect_to_oidc())],
                        None,
                    );
                    return Action::Pause;
                }
            },

            // If the token is not found, redirect to OIDC provider.
            None => {
                info!("Access denied: No token found.");
                // Redirect to OIDC provider.
                self.send_http_response(302, vec![("location", &HttpAuth.redirect_to_oidc())], None);
                return Action::Pause;
            }
        };
    }
}

impl Context for OIDCFlow {
    fn on_http_call_response(&mut self, _: u32, _: usize, _body_size: usize, _: usize) {
        info!("Access granted.");
        self.resume_http_request();
        return;
    }
}
