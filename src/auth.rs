// base64
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64engine, Engine as _};

// duration
use std::time::Duration;

// jwt
use jwt_simple::prelude::*;

// log
use log::{debug, warn};

// std
use std::sync::Arc;
use std::vec;

// proxy-wasm
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// url
use url::{form_urlencoded, Url};

use crate::config::PluginConfiguration;
use crate::discovery::OpenIdProvider;
use crate::error::PluginError;
use crate::html;
use crate::responses::{CodeCallback, ProviderSelectionCallback};
use crate::session;
use crate::session::{AuthorizationState, Session};

/// The `ConfiguredOidc is the main filter struct and responsible for the OpenID authentication flow.
/// Requests arriving are checked for a valid cookie. If the cookie is valid, the request is
/// forwarded. If the cookie is not valid, the user is redirected to the authorization endpoint.
pub struct ConfiguredOidc {
    /// The configuration of the filter which mainly contains the open id configuration and the
    /// keys to validate the JWT
    pub open_id_providers: Vec<OpenIdProvider>,
    /// Plugin configuration parsed from the envoy configuration
    pub plugin_config: Arc<PluginConfiguration>,
    /// Token id of the current request
    pub token_id: Option<u32>,
    /// ID of the current request
    pub request_id: String,
}

/// The context is used to process incoming HTTP requests when the filter is configured.
/// * If the host, path or URL is excluded, the request is forwarded.
/// * If the path matches the provider selection endpoint, the user is redirected to the authorization endpoint.
/// * If the path matches the redirect_uri, the code is exchanged for a token.
/// * If the cookie is valid, the request is forwarded.
/// * If the cookie is not valid, the user is redirected to the auth page or the authorization endpoint.
impl HttpContext for ConfiguredOidc {
    /// This function is called when the request headers are received.
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        // Get the host, path and scheme from the request headers
        let host = self.get_host().unwrap_or_default();
        let path = self.get_http_request_header(":path").unwrap_or_default();
        let scheme = self
            .get_http_request_header(":scheme")
            .unwrap_or("http".to_string());
        let url = Url::parse(&format!("{}://{}{}", scheme, host, path))
            .unwrap_or(Url::parse("http://example.com").unwrap());
        debug!("url: {}", url);

        // Get x-request-id
        if let Some(x_request_id) = self.get_http_request_header("x-request-id") {
            self.request_id = x_request_id
        }

        debug!("x-request-id: {}", self.request_id);

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

        // If the URL is one of the exclude URLs, forward the request
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

        // If Path is logout route, clear cookies and redirect to base path
        if path == self.plugin_config.logout_path {
            match self.logout() {
                Ok(action) => return action,
                Err(e) => {
                    warn!(
                        "logout failed for request {} with error: {}",
                        self.request_id, e
                    );
                    self.show_error_page(503, "Logout failed", "Please try again, delete your cookies or contact your system administrator.");
                }
            }
        }

        // If the path matches the provider selection endpoint, redirect to the authorization endpoint
        // with the selected provider.
        if path.contains("/_wasm-oidc-plugin/provider-selection") {
            let query = path.split('?').last().unwrap();

            // Deserialize the query into a struct
            let provider_selection_callback =
                serde_urlencoded::from_str::<ProviderSelectionCallback>(query).unwrap();
            // TODO: Error handling (crashes: https://localhost:10000/_wasm-oidc-plugin/provider-selection?n-a)

            // Find the provider to authorize with
            let provider_to_authorize_with = self
                .open_id_providers
                .iter()
                .find(|provider| {
                    provider.open_id_config.name
                        == provider_selection_callback.authorize_with_provider
                })
                .unwrap();
            // TODO: Error handling

            // Redirect to the authorization endpoint
            self.redirect_to_authorization_endpoint(
                provider_to_authorize_with,
                Some(provider_selection_callback.return_to),
            );
        }

        // If the path matches one of the `redirect_uri`s, exchange the code for a token
        if self
            .open_id_providers
            .iter()
            .any(|provider| path.starts_with(provider.open_id_config.redirect_uri.path()))
        {
            match self.exchange_code_for_token(path) {
                Ok(_) => return Action::Pause,
                Err(e) => {
                    warn!(
                        "token exchange failed for request {} with error: {}",
                        self.request_id, e
                    );
                    self.show_error_page(503, "Token exchange failed", "Please try again, delete your cookies or contact your system administrator.");
                }
            }
            return Action::Pause;
        }

        // Else, validate the cookie and forward the request if the authorization state is valid
        match self.validate_cookie() {
            Err(e) => match e {
                // disable logging for these errors
                PluginError::SessionCookieNotFoundError => {}
                PluginError::NonceCookieNotFoundError => {}
                _ => warn!("cookie validation failed: {}", e),
            },
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
        }

        // If any previous condition was not met, it means that the cookie is not valid or not present.
        //hThen, sow the auth page or redirect to the authorization endpoint (depending on the number of providers)
        self.generate_auth_page();

        // Pause the request
        Action::Pause
    }
}

/// This context is used to process HTTP responses from the token endpoint.
impl Context for ConfiguredOidc {
    /// This function catches the response from the token endpoint. We use an inner function to
    /// handle errors more easily.
    fn on_http_call_response(&mut self, token_id: u32, _: usize, body_size: usize, _: usize) {
        // Store the token in the cookie
        match self.store_token_in_cookie(token_id, body_size) {
            Ok(_) => {
                debug!("token stored in cookie");
            }
            Err(e) => {
                warn!(
                    "storing token in cookie failed for request {} with error: {}",
                    self.request_id, e
                );
                // Send a 503 if storing the token in the cookie failed
                self.show_error_page(
                    503,
                    "Storing Token in Cookie failed",
                    "Please try again, delete your cookies or contact your system administrator.",
                );
            }
        }
    }
}

/// Helper functions for the `ConfiguredOidc`` struct.
impl ConfiguredOidc {
    /// Check if the cookie is valid and if the token is valid.
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
            // If the cookie cannot be parsed, this function returns an error
            Err(e) => Err(PluginError::CookieValidationError(e.to_string())),
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
                        match self.validate_token(&auth_state.id_token, &session.issuer) {
                            // If the token is valid, this filter passes the request
                            Ok(_) => {
                                debug!("token is valid, passing request");
                                Ok(auth_state)
                            }
                            // If the token is invalid, the error is returned and the user is redirected to the auth page
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
        }
    }

    /// Validate the token using the JWT library and a given issuer.
    /// This function checks for the given issuer and audience and verifies the signature with the
    /// public keys loaded from the JWKs endpoint.
    ///
    /// ## Arguments
    /// * `token` - The token to validate
    /// * `issuer` - The issuer to validate the token against
    ///
    /// ## Returns
    ///
    /// A result with the following variants:
    /// * Ok(()) - If the token is valid
    /// * Err(PluginError) - If the token is invalid
    fn validate_token(&self, token: &str, issuer: &str) -> Result<(), PluginError> {
        // Get provider to use based on issuer
        let provider_to_use = match self
            .open_id_providers
            .iter()
            .find(|provider| provider.issuer == issuer)
        {
            Some(provider) => provider,
            None => {
                return Err(PluginError::ProviderNotFoundError(
                    "unknown issuer".to_string(),
                ));
            }
        };

        // Define allowed issuers and audiences
        let mut allowed_issuers = HashSet::new();
        allowed_issuers.insert(provider_to_use.issuer.clone());
        let mut allowed_audiences = HashSet::new();
        allowed_audiences.insert(provider_to_use.open_id_config.audience.clone());

        // Define verification options
        let verification_options = VerificationOptions {
            allowed_issuers: Some(allowed_issuers),
            allowed_audiences: Some(allowed_audiences),
            ..Default::default()
        };

        // Iterate over all public keys of the provider
        for public_key in provider_to_use.public_keys.iter() {
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
        // If no key worked for validation, return an error
        Err(PluginError::NoKeyError)
    }

    /// Exchange the code for a token using the token endpoint.
    /// This function is called when the user is redirected back to the callback URL.
    /// The code is extracted from the URL and exchanged for a token using the token endpoint.
    ///
    /// ## Arguments
    ///
    /// * `path` - The path of the request
    ///
    /// ## Returns
    ///
    /// * Ok(()) - If the token is exchanged successfully
    /// * Err(PluginError) - If the token exchange fails
    fn exchange_code_for_token(&mut self, path: String) -> Result<(), PluginError> {
        debug!("received request for OpenID callback");

        // Get Query String from URL
        let query = path.split('?').last().unwrap_or_default();
        debug!("query: {}", query);

        // Get state from query
        let callback_params = serde_urlencoded::from_str::<CodeCallback>(query)?;

        // Get cookie and nonce
        let encoded_cookie = self.get_session_cookie_as_string()?;
        let encoded_nonce = self.get_nonce()?;

        // Get session
        let session = Session::decode_and_decrypt(
            encoded_cookie,
            self.plugin_config.aes_key.reveal().clone(),
            encoded_nonce,
        )?;

        // Get issuer from session
        let issuer = session.issuer.clone();

        // Get provider to use based on issuer
        let provider_to_use = match self
            .open_id_providers
            .iter()
            .find(|provider| provider.issuer == issuer)
        {
            Some(provider) => provider,
            None => {
                return Err(PluginError::ProviderNotFoundError(
                    "unknown issuer".to_string(),
                ));
            }
        };

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
                    provider_to_use.open_id_config.client_id,
                    provider_to_use.open_id_config.client_secret.reveal()
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
            .append_pair(
                "redirect_uri",
                provider_to_use.open_id_config.redirect_uri.as_str(),
            )
            .append_pair("state", &state)
            .finish();

        // Dispatch request to token endpoint using built-in envoy function
        debug!("sending data to token endpoint: {}", data);
        match self.dispatch_http_call(
            &provider_to_use.open_id_config.upstream_cluster,
            vec![
                (":method", "POST"),
                (":path", provider_to_use.token_endpoint.path()),
                (
                    ":authority",
                    provider_to_use.open_id_config.authority.as_str(),
                ),
                ("Authorization", &auth),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            Some(data.as_bytes()),
            vec![],
            Duration::from_secs(10),
        ) {
            // If the request fails, this filter logs the error and pauses the request
            Err(_) => Err(PluginError::DispatchError),
            // If the request is dispatched successfully, this filter pauses the request
            Ok(id) => {
                self.token_id = Some(id);
                Ok(())
            }
        }
    }

    /// Store the token from the token response in an encrypted cookie.
    ///
    /// ## Arguments
    ///
    /// * `token_id` - The token id of the response
    /// * `body_size` - The size of the response body
    ///
    /// ## Returns
    ///
    /// * Ok(()) - If the token is stored in the cookie successfully
    /// * Err(PluginError) - If the token could not be stored in the cookie
    fn store_token_in_cookie(
        &mut self,
        token_id: u32,
        body_size: usize,
    ) -> Result<(), PluginError> {
        // Assess token id
        if self.token_id != Some(token_id) {
            return Err(PluginError::TokenIdMismatchError);
        }

        // Check if the response is valid. If its not 200, investigate the response and log the error.
        if self.get_http_call_response_header(":status") != Some("200".to_string()) {
            // Get body of response
            match self.get_http_call_response_body(0, body_size) {
                // If no body is found, log the error
                None => return Err(PluginError::NoBodyError),
                Some(body) => {
                    // Parse body
                    match String::from_utf8(body) {
                        Ok(decoded) => return Err(PluginError::TokenResponseFormatError(decoded)),
                        // If parsing fails, log the error
                        Err(e) => return Err(PluginError::Utf8Error(e)),
                    }
                }
            }
        }

        // Previously we checked for the status code and the body, so we can assume that the response is valid.
        match self.get_http_call_response_body(0, body_size) {
            // If no body is found, return the error
            None => Err(PluginError::CookieStoreError(
                "No body in response".to_string(),
            )),
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

                // Parse authorization state from token response
                let authorization_state = serde_json::from_slice::<AuthorizationState>(&body)?;
                debug!("authorization state: {:?}", authorization_state);

                // Add authorization state to session
                session.authorization_state = Some(authorization_state);

                // Re-encrypt and re-encode session
                let (new_session, new_nonce) =
                    session.encrypt_and_encode(self.plugin_config.aes_key.reveal().clone())?;

                // Build cookie values
                let set_cookie_values = Session::make_cookie_values(
                    &new_session,
                    &new_nonce,
                    self.plugin_config.cookie_name.as_str(),
                    self.plugin_config.cookie_duration,
                );

                // Build cookie headers
                let mut headers = Session::make_set_cookie_headers(&set_cookie_values);

                // Set the location header to the original path
                let location_header = ("Location", session.original_path.as_str());
                headers.push(location_header);

                // Redirect back to the original URL and set the cookie.
                self.send_http_response(307, headers, Some(b"Redirecting..."));
                debug!("token stored in cookie");
                Ok(())
            }
        }
    }

    /// Clear the cookies and redirect to the base path or `end_session_endpoint`.
    fn logout(&self) -> Result<Action, PluginError> {
        let cookie_values = Session::make_cookie_values("", "", &self.plugin_config.cookie_name, 0);

        let mut headers = Session::make_set_cookie_headers(&cookie_values);

        // Get session from cookie
        let cookie = self.get_session_cookie_as_string()?;
        let nonce = self.get_nonce()?;
        let session = Session::decode_and_decrypt(
            cookie,
            self.plugin_config.aes_key.reveal().clone(),
            nonce,
        )?;

        // Get provider to use based on issuer because the end session endpoint is provider-specific
        let provider = self
            .open_id_providers
            .iter()
            .find(|provider| provider.issuer == session.issuer)
            .unwrap();
        // TODO: Error handling

        // Redirect to end session endpoint, if available (not all OIDC providers support this)
        let location = match &provider.end_session_endpoint {
            // if the end session endpoint is available, redirect to it
            Some(url) => url.as_str(),
            // else, redirect to the base path
            None => "/",
        };
        headers.push(("Location", location));
        headers.push(("Cache-Control", "no-cache"));

        self.send_http_response(307, headers, Some(b"Logging out..."));

        Ok(Action::Pause)
    }

    /// Show the auth page or redirect to the authorization endpoint.
    fn generate_auth_page(&self) {
        // If there is more than one provider, show an auth page where the user selects the provider
        if self.open_id_providers.len() > 1 {
            debug!("no cookie found or invalid, showing auth page");

            // Grab the original path and encode it
            let original_path = self
                .get_http_request_header(":path")
                .unwrap_or("/".to_string());
            let original_path_encoded = base64engine.encode(original_path.as_bytes());

            let mut urls = vec![];
            let mut provider_cards = String::new();

            // Create a card for each provider which sends the user back to the plugin with the selected provider
            for open_id_provider in self.open_id_providers.iter() {
                let url = format!(
                    "/_wasm-oidc-plugin/provider-selection?authorize_with_provider={}&return_to={}",
                    open_id_provider.open_id_config.name, original_path_encoded
                );
                urls.push(url.clone());

                let provider_card = html::provider_card(
                    &url,
                    open_id_provider.open_id_config.name.as_str(),
                    open_id_provider.open_id_config.image.as_str(),
                );
                provider_cards.push_str(&provider_card);
            }

            let headers = vec![("cache-control", "no-cache"), ("content-type", "text/html")];

            // Show the auth page
            self.send_http_response(
                200,
                headers,
                Some(html::auth_page_html(provider_cards).as_bytes()),
            );
        } else {
            // If there is only one provider, redirect the user to the authorization endpoint right away
            debug!("no cookie found or invalid, redirecting to authorization endpoint");
            self.redirect_to_authorization_endpoint(self.open_id_providers.first().unwrap(), None);
        }
    }

    /// Redirect to the `authorization_endpoint` by sending a HTTP response with a 307 status code.
    /// This function generates a PKCE code verifier and challenge, creates a session struct, encrypts
    /// and encodes the session, and sets the cookie headers.
    ///
    /// ## Arguments
    ///
    /// * `open_id_provider` - The OpenID provider to redirect to
    /// * `return_to` - The original path to redirect to after login
    pub fn redirect_to_authorization_endpoint(
        &self,
        open_id_provider: &OpenIdProvider,
        return_to: Option<String>,
    ) -> Action {
        // The `original_path` is the path to which the user should be redirected after login. and it can be
        // passed as a query parameter. If the `return_to` parameter is not set, the original path is the current path
        // (this is the case when there is only one provider).
        let original_path: String = match return_to {
            Some(return_to) => match base64engine.decode(return_to.as_bytes()) {
                Ok(decoded) => match String::from_utf8(decoded) {
                    Ok(decoded) => decoded,
                    Err(_) => "/".to_string(),
                },
                Err(_) => "/".to_string(),
            },
            None => self
                .get_http_request_header(":path")
                .unwrap_or("/".to_string()),
        };

        // Generate PKCE code verifier and challenge
        let pkce_verifier = pkce::code_verifier(128);
        let pkce_verifier_string = String::from_utf8(pkce_verifier.clone()).unwrap();
        let pkce_challenge = pkce::code_challenge(&pkce_verifier);

        // Generate state
        let state_string = String::from_utf8(pkce::code_verifier(128)).unwrap();

        // Create session struct and encrypt it
        let (session, nonce) = session::Session {
            issuer: open_id_provider.issuer.clone(),
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
        );

        // Build cookie headers
        let mut headers = Session::make_set_cookie_headers(&set_cookie_values);

        let claims =
            serde_json::to_string(&open_id_provider.open_id_config.claims).unwrap_or_default();

        // Build URL
        let location = Url::parse_with_params(
            open_id_provider.auth_endpoint.as_str(),
            &[
                ("response_type", "code"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
                ("state", &state_string),
                ("client_id", &open_id_provider.open_id_config.client_id),
                (
                    "redirect_uri",
                    open_id_provider.open_id_config.redirect_uri.as_str(),
                ),
                ("scope", &open_id_provider.open_id_config.scope),
                ("claims", &claims),
            ],
        )
        .unwrap();

        headers.push(("Location", location.as_str()));

        self.send_http_response(307, headers, Some(b"Redirecting..."));

        Action::Pause
    }

    /// Get the cookie of the HTTP request by name
    ///
    /// ## Arguments
    ///
    /// * `name` - The name of the cookie to search for
    ///
    /// ## Returns
    /// The value of the cookie if found, None otherwise
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
    ///
    /// ## Returns
    ///
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

    /// Helper function to get the session cookie as a string by getting the cookie from the request
    /// headers and concatenating all cookie parts.
    ///
    /// ## Returns
    ///
    /// The session cookie as a string if found, an error otherwise
    pub fn get_session_cookie_as_string(&self) -> Result<String, PluginError> {
        let cookie_name = &self.plugin_config.cookie_name;

        // Get the number of cookie parts
        let num_parts: u8 = self
            .get_cookie(&format!("{cookie_name}-parts"))
            .unwrap_or_default()
            .parse()
            .map_err(|_| PluginError::SessionCookieNotFoundError)?;

        // Get the cookie parts and concatenate them into a string
        let values = (0..num_parts)
            .map(|i| self.get_cookie(&format!("{cookie_name}-{i}")))
            .collect::<Option<Vec<String>>>()
            .ok_or(PluginError::SessionCookieNotFoundError)?
            .join("");

        Ok(values)
    }

    // Get the encoded nonce from the cookie
    pub fn get_nonce(&self) -> Result<String, PluginError> {
        self.get_cookie(format!("{}-nonce", self.plugin_config.cookie_name).as_str())
            .ok_or(PluginError::NonceCookieNotFoundError)
    }
}
