// proxy-wasm
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// log
use log::{debug, info, warn};

// arc
use std::sync::Arc;

// url
use url::Url;

// base64
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as base64engine_urlsafe, Engine as _};

// duration
use std::time::Duration;

// crate
use crate::{OpenIdConfig, OidcAuth};
use crate::config::PluginConfiguration;
use crate::responses::{JWKsResponse, OidcDiscoveryResponse};

proxy_wasm::main! {{

    proxy_wasm::set_log_level(LogLevel::Trace);

    info!("Starting OIDC plugin");

    // This sets the root context, which is the first context that is called on startup.
    // The root context is used to initialize the plugin and load the configuration from the
    // plugin config and the discovery endpoints.
    // Here, we set all values to None, so that the plugin can be initialized.
    // The mode is set to LoadingConfig, so that the plugin knows that it is still loading the
    // configuration.
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(OidcDiscovery {
        state: OidcRootState::Uniitialized,
        token_id: None
    }) });
}}

/// This context is responsible for getting the OIDC configuration and setting the http context.
pub struct OidcDiscovery {
    /// The state of the root context
    pub state: OidcRootState,
    /// Tokenid of the HttpCalls to verify the call is correct
    token_id: Option<u32>,
}

/// The mode of the root context
#[derive(Debug, Clone)]
pub enum OidcRootState {
    // State when the plugin needs to load the plugin configuration
    Uniitialized,
    /// The root context is loading the configuration from the open id discovery endpoint
    LoadingConfig {
        /// Plugin config
        plugin_config: Arc<PluginConfiguration>,
    },
    /// The root context is loading the jwks configuration
    LoadingJwks{
        /// Plugin config
        plugin_config: Arc<PluginConfiguration>,

        /// The authorization endpoint
        auth_endpoint: Url,
        /// The token endpoint
        token_endpoint: Url,
        /// The issuer
        issuer: String,
        /// The url from which the public key can be retrieved
        jwks_uri: Url,
    },
    /// The root context is ready
    Ready{

        /// Plugin config
        plugin_config: Arc<PluginConfiguration>,
        /// Filter config
        filter_config: Arc<OpenIdConfig>,
    },
}

/// The root context is used to create new HTTP contexts and load configuration.
impl RootContext for OidcDiscovery {

    /// Called when proxy is being configured.
    /// This is where the plugin configuration is loaded.
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        // TODO: Load configuration from plugin configuration such as cookie settings, etc.

        info!("Plugin is configuring");

        // Load the configuration from the plugin configuration.
        match self.get_plugin_configuration() {
            Some(config_bytes) => {
                debug!("got plugin configuration");

                // Parse the configuration in a yaml format.
                match serde_yaml::from_slice::<PluginConfiguration>(&config_bytes) {
                    Ok(plugin_config) => {
                        debug!("parsed plugin configuration");

                        // Set the plugin configuration and mode to LoadingConfig.
                        self.state = OidcRootState::LoadingConfig {
                            plugin_config: Arc::new(plugin_config),
                        };

                        // Tick immediately to load the configuration.
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

    /// The root context is ticking every 2 seconds as long as the configuration is not loaded yet.
    /// On every tick, the mode is checked and the corresponding action is taken.
    /// 1. If the mode is `Uniitialized`, the configuration is loaded from the plugin configuration.
    /// 2. If the mode is `LoadingConfig`, the configuration is loaded from the openid configuration endpoint.
    /// 3. If the mode is `LoadingJwks`, the public key is loaded from the jwks endpoint.
    /// 4. If the mode is `Ready`, the configuration is reloaded.
    fn on_tick(&mut self) {
        debug!("tick");

        // See what the current state is.
        match &self.state {
            // This state is not possible, but is here to make the compiler happy.
            OidcRootState::Uniitialized => {
                warn!("plugin is not initialized");

            }

            // If the plugin is in Loading `LoadingConfig` mode, the configuration is loaded from the
            // openid configuration endpoint.
            OidcRootState::LoadingConfig{
                plugin_config,
            } => {

                // Tick every 400ms
                self.set_tick_period(Duration::from_millis(400));

                // Make call to openid configuration endpoint
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

            // If the plugin is in Loading `LoadingJwks` mode, the public key is loaded from the
            // jwks endpoint.
            OidcRootState::LoadingJwks{
                plugin_config,
                jwks_uri,
                ..
            }  => {

                // Make call to jwks endpoint and load public key
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
                // This is controller by `reload_interval_in_h` in the plugin configuration.
                // This is done by setting the mode to `LoadingConfig` again.
                self.state = OidcRootState::LoadingConfig{
                    plugin_config: plugin_config.clone(),
                };
                self.set_tick_period(Duration::from_millis(1));

            }
        }
    }

    /// Creates the http context with the information from the filter_config and the plugin configuration.
    /// This is called whenever a new http context is created by the proxy.
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        info!("Creating http context with root context information.");

        match &self.state {
            OidcRootState::Ready {
                filter_config,
                plugin_config,
            } => {
                // Return the http context.
                return Some(Box::new(OidcAuth {
                    filter_config: filter_config.clone(),
                    plugin_config: plugin_config.clone(),
                }));
            },
            _ => {
                // TODO: Able to crash the plugin here during 400ms after startup.
                warn!("Cannot create http context, as the plugin is not ready.");
                return None;
            }
        }
    }

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
        // Set the state to the next state, if applicable.
        self.state = match &self.state {

            // This state is not possible, but is here to make the compiler happy.
            OidcRootState::Uniitialized => {
                warn!("plugin is not initialized");
                OidcRootState::Uniitialized
            },

            // If the plugin is in Loading `LoadingConfig` mode, the configuration is loaded from the
            // openid configuration endpoint.
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

                // Output body
                let body = self.get_http_call_response_body(0, _body_size).unwrap();

                // Parse body
                // TODO: Stuct for config response in `responses.rs`
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

                // Output body
                let body = self.get_http_call_response_body(0, _body_size).unwrap();

                // Parse body
                match serde_json::from_slice::<JWKsResponse>(&body) {
                    Ok(jwks_response) => {
                        debug!("parsed jwks body: {:?}", jwks_response);

                        // Check if keys are present
                        if jwks_response.keys.len() == 0 {
                            warn!("no keys found in jwks response, retry in 1 minute");
                            self.set_tick_period(Duration::from_secs(60));
                            return;
                        }

                        // Select the key that is of alg RS256 and the newest.
                        let jwk = jwks_response.keys.iter()
                            .filter(|key| key.alg == "RS256")
                            .last()
                            .unwrap();

                        // Extract public key components
                        let public_key_comp_n = &jwk.n;
                        let public_key_comp_e = &jwk.e;

                        // Decode and parse the public key
                        let n_dec = base64engine_urlsafe.decode(public_key_comp_n).unwrap();
                        let e_dec = base64engine_urlsafe.decode(public_key_comp_e).unwrap();
                        let public_key =
                            jwt_simple::algorithms::RS256PublicKey::from_components(&n_dec, &e_dec)
                                .unwrap();

                        // Set the tick period to the reload interval.
                        self.set_tick_period(Duration::from_secs(plugin_config.reload_interval_in_h * 3600));
                        info!("All configuration loaded. Filter is ready. Refreshing config in {} hour(s).",
                            plugin_config.reload_interval_in_h);

                        // Set the mode to ready.
                        OidcRootState::Ready {
                            filter_config: Arc::new(OpenIdConfig {
                                auth_endpoint: auth_endpoint.clone(),
                                token_endpoint: token_endpoint.clone(),
                                issuer: issuer.clone(),
                                public_key,
                            }),
                            plugin_config: plugin_config.clone(),
                        }
                    }
                    Err(e) =>  {
                        warn!("error parsing jwks body: {:?}", e);
                        // Stay in the same mode.
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
        }
    }
}

