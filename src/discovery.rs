// proxy-wasm
use proxy_wasm::hostcalls;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// log
use log::{debug, info, warn};

// arc
use std::sync::Arc;
use std::sync::Mutex;

// url
use url::Url;

// base64
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as base64engine_urlsafe, Engine as _};

// duration
use std::time::Duration;

// crate
use crate::{OpenIdConfig, ConfiguredOidc, UnconfiguredOidc};
use crate::config::PluginConfiguration;
use crate::responses::{JWKsResponse, OidcDiscoveryResponse};

// This is the initial entry point of the plugin.
proxy_wasm::main! {{

    proxy_wasm::set_log_level(LogLevel::Trace);

    info!("Starting OIDC plugin");

    // This sets the root context, which is the first context that is called on startup.
    // The root context is used to initialize the plugin and load the configuration from the
    // plugin config and the discovery endpoints.
    // Here, we set state to uninitialized, which means that the plugin is not yet configured.
    // The state will be changed to LoadingConfig when the plugin configuration is loaded.
    // The token_id is used to verify that the http responses match the dispatches which are
    // sent to the discovery endpoints.
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(OidcDiscovery {
        state: OidcRootState::Uninitialized,
        waiting: Mutex::new(Vec::new()),
        token_id: None,
    }) });
}}

/// This context is responsible for getting the OIDC configuration, jwks keys
/// and setting the http context.
pub struct OidcDiscovery {
    /// The state of the root context. This is an enum which has the following variants:
    /// - Uninitialized: The plugin is not yet configured
    /// - LoadingConfig: The plugin configuration is being loaded
    /// - LoadingJwks: The jwks configuration is being loaded
    /// - Ready: The plugin is ready
    pub state: OidcRootState,
    /// Queue of waiting requests which are waiting for the configuration to be loaded
    waiting: Mutex<Vec<u32>>,
    /// Tokenid of the HttpCalls to verify the call is correct
    token_id: Option<u32>,
}

/// The state of the root context is an enum which has the following variants:
/// - Uninitialized: The plugin is not yet configured
/// - LoadingConfig: The plugin configuration is being loaded
/// - LoadingJwks: The jwks configuration is being loaded
/// - Ready: The plugin is ready
/// Each state has a different set of fields which are needed for that specific state.
#[derive(Debug)]
pub enum OidcRootState {
    /// State when the plugin needs to load the plugin configuration
    Uninitialized,
    /// The root context is loading the configuration from the open id discovery endpoint
    LoadingConfig {
        /// Plugin config loaded from the envoy configuration
        plugin_config: Arc<PluginConfiguration>,
    },
    /// The root context is loading the jwks configuration
    LoadingJwks{
        /// Plugin config
        plugin_config: Arc<PluginConfiguration>,

        /// The authorization endpoint to start the code flow
        auth_endpoint: Url,
        /// The token endpoint to exchange the code for a token
        token_endpoint: Url,
        /// The issuer
        issuer: String,
        /// The url from which the public keys can be retrieved
        jwks_uri: Url,
    },
    /// The root context is ready
    Ready{
        /// Plugin config loaded from the envoy configuration
        plugin_config: Arc<PluginConfiguration>,
        /// Filter config loaded from the open id discovery endpoint and the jwks endpoint
        filter_config: Arc<OpenIdConfig>,
    },
}

/// The root context is used to create new HTTP contexts and load configuration from the
/// open id discovery endpoint and the jwks endpoint.
/// When `on_configure` is called, the plugin configuration is loaded and the state is set to
/// LoadingConfig. The filter is then ticked immediately to load the configuration.
/// When `on_http_call_response` is called, the Open ID response is parsed and the state is set to
/// LoadingJwks.
/// On the next tick, the jwks endpoint is called and the state is set to Ready once the jwks
/// response is received and successfully parsed.
impl RootContext for OidcDiscovery {

    /// Called when proxy is being configured.
    /// This is where the plugin configuration is loaded and the next state is set.
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {

        info!("Plugin is configuring");

        // Load the configuration from the plugin configuration.
        match self.get_plugin_configuration() {
            Some(config_bytes) => {
                debug!("got plugin configuration");

                // Parse the configuration in a yaml format.
                match serde_yaml::from_slice::<PluginConfiguration>(&config_bytes) {
                    Ok(plugin_config) => {
                        debug!("parsed plugin configuration");

                        // Advance to the next state and store the plugin configuration.
                        self.state = OidcRootState::LoadingConfig {
                            plugin_config: Arc::new(plugin_config),
                        };

                        // Tick immediately to load the configuration.
                        // See `on_tick` for more information.
                        self.set_tick_period(Duration::from_millis(1));

                        return true;
                    }
                    Err(e) => warn!("error parsing plugin configuration: {:?}", e),
                }
            }
            None => warn!("no plugin configuration"),
        }

        false
    }

    /// Creates the http context with the information from the filter_config and the plugin configuration.
    /// This is called whenever a new http context is created by the proxy.
    /// When the plugin is not yet ready, the http context is created in Unconfigured state and the
    /// context id is added to the waiting queue to be processed later.
    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {

        match &self.state {

            // If the plugin is ready, create the http context in Ready state
            // with the filter config and the plugin config.
            OidcRootState::Ready {
                filter_config,
                plugin_config,
            } => {
                debug!("Creating http context with root context information.");

                // Return the http context.
                return Some(Box::new(ConfiguredOidc {
                    filter_config: filter_config.clone(),
                    plugin_config: plugin_config.clone(),
                    token_id: None,
                }));
            },

            // If the plugin is not ready, return the http context in Unconfigured state and add the
            // context id to the waiting queue.
            _ => {
                warn!("Root context is not ready yet. Queueing http context.");

                // Add the context id to the waiting queue.
                self.waiting.lock().unwrap().push(context_id);

                // Return the http context in Unconfigured state.
                return Some(Box::new(UnconfiguredOidc{
                    original_path: None,
                }));
            }
        }
    }

    /// The root context is ticking every 400 millis as long as the configuration is not loaded yet.
    /// On every tick, the mode is checked and the corresponding action is taken.
    /// 1. If the mode is `Uninitialized`, the configuration is loaded from the plugin configuration.
    /// 2. If the mode is `LoadingConfig`, the configuration is loaded from the openid configuration endpoint.
    /// 3. If the mode is `LoadingJwks`, the public key is loaded from the jwks endpoint.
    /// 4. If the mode is `Ready`, the configuration is reloaded.
    fn on_tick(&mut self) {
        debug!("tick");

        // See what the current state is.
        match &self.state {

            // This state is not possible, but is here to make the compiler happy.
            OidcRootState::Uninitialized => {
                warn!("plugin is not initialized");

            }

            // If the plugin is in Loading `LoadingConfig` mode, the configuration is loaded from the
            // openid configuration endpoint.
            OidcRootState::LoadingConfig{
                plugin_config,
            } => {

                // Tick every 250ms to not overload the openid configuration endpoint.
                self.set_tick_period(Duration::from_millis(3000));

                // Make call to openid configuration endpoint
                // The reponse is handled in `on_http_call_response`.
                match self.dispatch_http_call(
                    "oidc",
                    vec![
                        (":method", "GET"),
                        (":path", &plugin_config.config_endpoint),
                        (":authority", plugin_config.authority.as_str()),
                    ],
                    None,
                    vec![],
                    Duration::from_secs(5),
                ) {
                    Ok(id) => {
                        debug!("dispatched openid config call");
                        self.token_id = Some(id);
                    },
                    Err(e) => warn!("error dispatching oidc call: {:?}", e),
                }
                return;
            }

            // If the plugin is in Loading `LoadingJwks` mode, the public keys are loaded from the
            // jwks endpoint.
            OidcRootState::LoadingJwks{
                plugin_config,
                jwks_uri,
                ..
            }  => {

                // Make call to jwks endpoint and load public key
                // The reponse is handled in `on_http_call_response`.
                match self.dispatch_http_call(
                    "oidc",
                    vec![
                        (":method", "GET"),
                        (":path", jwks_uri.as_str()),
                        (":authority", plugin_config.authority.as_str()),
                    ],
                    None,
                    vec![],
                    Duration::from_secs(5),
                ) {
                    Ok(id) => {
                        debug!("dispatched jwks call");
                        self.token_id = Some(id);
                    }
                    Err(e) => warn!("error dispatching jwks call: {:?}", e),
                }
            }
            OidcRootState::Ready{
                filter_config: _,
                plugin_config,
            }=> {

                // If this state is reached, the plugin was ready and needs to reload the configuration.
                // This is controlled by `reload_interval_in_h` in the plugin configuration.
                // The state is set to `LoadingConfig` and the tick period is set to 1ms to load the configuration.
                self.state = OidcRootState::LoadingConfig{
                    plugin_config: plugin_config.clone(),
                };
                self.set_tick_period(Duration::from_millis(1));

            }
        }
    }

    /// This is one of those functions that need to be there for some reason but we are
    /// not sure why. It just doesnt work without it.
    fn get_type(&self) -> Option<proxy_wasm::types::ContextType> {
        Some(ContextType::HttpContext)
    }
}

/// The context is used to process the response from the OIDC config endpoint and the jwks endpoint.
/// It also utilised the mode enum to determine what to do with the response.
/// 1. If the mode is `Uninitialized`, the plugin is not initialized and the response is ignored.
/// 2. If the mode is `LoadingConfig`, the open id configuration is expected.
/// 3. If the mode is `LoadingJwks`, the jwks endpoint is expected.
/// 4. `Ready` is not expected, as the root context doesn't dispatch any calls in that mode.
impl Context for OidcDiscovery {
    fn on_http_call_response(&mut self, token_id: u32, _num_headers: usize, _body_size: usize, _num_trailers: usize,
    ) {
        // Check for each state what to do with the response.
        self.state = match &self.state {

            // This state is not possible, but is here to make the compiler happy.
            OidcRootState::Uninitialized => {
                warn!("plugin is not initialized");
                OidcRootState::Uninitialized
            },

            // If the plugin is in Loading `LoadingConfig` mode, the response is expected to be the
            // openid configuration.
            OidcRootState::LoadingConfig{
                plugin_config,
            } => {
                // If the token id is not the same as the one from the call made in
                // `self.dispatch_http_call`, the response is ignored.
                if self.token_id != Some(token_id) {
                    warn!("unexpected token id");
                    return;
                }

                debug!("loading from openid config endpoint");

                // Parse the response body as json.
                let body = self.get_http_call_response_body(0, _body_size).unwrap();

                // Parse body
                match serde_json::from_slice::<OidcDiscoveryResponse>(&body) {
                    Ok(open_id_response) => {
                        debug!("parsed config response: {:?}", open_id_response);

                        // Set the mode to loading jwks.
                        OidcRootState::LoadingJwks {
                            plugin_config: plugin_config.clone(),
                            auth_endpoint: Url::parse(&open_id_response.authorization_endpoint).unwrap(),
                            token_endpoint: Url::parse(&open_id_response.token_endpoint).unwrap(),
                            issuer: open_id_response.issuer,
                            jwks_uri: Url::parse(&open_id_response.jwks_uri).unwrap(),
                        }
                    }
                    Err(e) => {
                        warn!("error parsing config response: {:?}", e);
                        // Stay in the same mode.
                        OidcRootState::LoadingConfig{
                            plugin_config: plugin_config.clone(),
                        }
                    }
                }
            }

            // If the plugin is in `LoadingJwks` mode, the jwks endpoint is expected.
            OidcRootState::LoadingJwks{
                plugin_config,
                auth_endpoint,
                token_endpoint,
                issuer,
                jwks_uri,
            } => {

                // If the token id is not the same as the one from the call, return.
                if self.token_id != Some(token_id) {
                    warn!("unexpected token id");
                    return;
                }

                debug!("loading jwks");

                // Parse body
                let body = self.get_http_call_response_body(0, _body_size).unwrap();
                match serde_json::from_slice::<JWKsResponse>(&body) {
                    Ok(jwks_response) => {
                        debug!("parsed jwks body: {:?}", jwks_response);

                        // Check if keys are present
                        if jwks_response.keys.len() == 0 {
                            warn!("no keys found in jwks response, retry in 1 minute");
                            self.set_tick_period(Duration::from_secs(60));
                            return;
                        }

                       // For all keys, check if it is a key of alg RS256 and append it to the list of keys.
                       let mut keys : Vec<jwt_simple::algorithms::RS256PublicKey> = Vec::new();
                       for key in jwks_response.keys {
                            if key.kty == "RSA" && key.alg == "RS256" {
                                // If the key id is present, set the state to ready and return.
                                // Extract public key components
                                let public_key_comp_n = &key.n;
                                let public_key_comp_e = &key.e;

                                // Decode and parse the public key
                                let n_dec = base64engine_urlsafe.decode(public_key_comp_n).unwrap();
                                let e_dec = base64engine_urlsafe.decode(public_key_comp_e).unwrap();

                                let public_key = jwt_simple::algorithms::RS256PublicKey::from_components(&n_dec, &e_dec)
                                .unwrap();

                                keys.push(public_key);
                            }
                        }

                        // Now that we have loaded all the configuration, we can set the tick period
                        // to the configured value and advance to the ready state.
                        self.set_tick_period(Duration::from_secs(plugin_config.reload_interval_in_h * 3600));
                        info!("All configuration loaded. Filter is ready. Refreshing config in {} hour(s).",
                            plugin_config.reload_interval_in_h);

                        // Set the mode to ready.
                        OidcRootState::Ready {
                            filter_config: Arc::new(OpenIdConfig {
                                auth_endpoint: auth_endpoint.clone(),
                                token_endpoint: token_endpoint.clone(),
                                issuer: issuer.clone(),
                                public_keys: keys,
                            }),
                            plugin_config: plugin_config.clone(),
                        }
                    }
                    Err(e) =>  {
                        warn!("error parsing jwks body: {:?}", e);
                        // Stay in the same mode as the response couldnt be parsed.
                        OidcRootState::LoadingJwks {
                            plugin_config: plugin_config.clone(),
                            auth_endpoint: auth_endpoint.clone(),
                            token_endpoint: token_endpoint.clone(),
                            issuer: issuer.clone(),
                            jwks_uri: jwks_uri.clone(),
                        }
                    }
                }
            }

            // If the plugin is in `Ready` mode, the response is ignored and the mode is not changed.
            OidcRootState::Ready {
                plugin_config,
                filter_config,
            }=> {
                warn!("ready mode is not expected here");
                OidcRootState::Ready {
                    plugin_config: plugin_config.clone(),
                    filter_config: filter_config.clone(),
                }
            }
        };
        // If the plugin is in `Ready` mode, any request that was sent during the loading phase,
        // is now resumed.
        if matches!(self.state, OidcRootState::Ready { .. }) {
            for context_id in self.waiting.lock().unwrap().drain(..) {
                info!("resuming queued request with id {}", context_id);
                hostcalls::set_effective_context(context_id).unwrap();
                hostcalls::resume_http_request().unwrap();
            }
            // hostcalls::set_effective_context(1).unwrap();
        }
    }
}

