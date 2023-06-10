// proxy-wasm
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// log
use log::{debug, info, warn};

// url
use url::Url;

// base64
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as base64engine_urlsafe, Engine as _};

// duration
use std::time::Duration;

// crate
use crate::config::PluginConfiguration;
use crate::{FilterConfig, OIDCFlow};

proxy_wasm::main! {{

    proxy_wasm::set_log_level(LogLevel::Trace);

    info!("Starting OIDC plugin");

    // This sets the root context, which is the first context that is called on startup.
    // The root context is used to initialize the plugin and load the configuration from the
    // plugin config and the discovery endpoints.
    // Here, we set all values to None, so that the plugin can be initialized.
    // The mode is set to LoadingConfig, so that the plugin knows that it is still loading the
    // configuration.
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(OIDCRoot {
        plugin_config: None,
        auth_endpoint: None,
        token_endpoint: None,
        issuer: None,
        mode: OIDCRootMode::LoadingConfig,
        jwks_uri: None,
        public_key: None,
    }) });
}}

/// This context is responsible for getting the OIDC configuration and setting the http context.
pub struct OIDCRoot {
    /// Plugin config
    pub plugin_config: Option<PluginConfiguration>,

    /// The authorization endpoint
    pub auth_endpoint: Option<Url>,
    /// The token endpoint
    pub token_endpoint: Option<Url>,
    /// The issuer
    pub issuer: Option<String>,
    /// Mode of the root context
    pub mode: OIDCRootMode,
    /// The url from which the public key can be retrieved
    pub jwks_uri: Option<Url>,
    /// The public key
    pub public_key: Option<jwt_simple::algorithms::RS256PublicKey>,
}

/// The mode of the root context
#[derive(Debug, PartialEq)]
pub enum OIDCRootMode {
    /// The root contex is loading the configuration
    LoadingConfig,
    /// The root context is loading the jwks configuration
    LoadingJwks,
    /// The root context is ready
    Ready,
}

/// The root context is used to create new HTTP contexts and load configuration.
impl RootContext for OIDCRoot {

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
                    Ok(parsed) => {
                        debug!("parsed plugin configuration");

                        // Set the plugin configuration.
                        self.plugin_config = Some(parsed);

                        // Tick every 500ms
                        self.set_tick_period(Duration::from_millis(500));

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
    /// 1. If the mode is `LoadingConfig`, the configuration is loaded from the openid configuration endpoint.
    /// 2. If the mode is `LoadingJwks`, the public key is loaded from the jwks endpoint.
    /// 3. If the mode is `Ready`, the configuration is reloaded.
    fn on_tick(&mut self) {
        debug!("tick");

        // If the open id configuration is not yet loaded, try to load it.
        match self.mode {
            OIDCRootMode::LoadingConfig => {
                // Make call to openid configuration endpoint
                match self.dispatch_http_call(
                    "oidc",
                    vec![
                        (":method", "GET"),
                        (":path", self.plugin_config.as_ref().unwrap().config_endpoint.as_str()),
                        (":authority", self.plugin_config.as_ref().unwrap().authority.as_str()),
                    ],
                    None,
                    vec![],
                    Duration::from_secs(5),
                ) {
                    Ok(_) => debug!("dispatched openid config call"),
                    Err(e) => warn!("error dispatching oidc call: {:?}", e),
                }
                return;
            }
            OIDCRootMode::LoadingJwks => {
                // Extract path from jwks_uri
                let jwks_uri = self.jwks_uri.as_ref().unwrap().as_str();

                // Make call to jwks endpoint and load public key
                match self.dispatch_http_call(
                    "oidc",
                    vec![
                        (":method", "GET"),
                        (":path", &jwks_uri),
                        (":authority", self.plugin_config.as_ref().unwrap().authority.as_str()),
                    ],
                    None,
                    vec![],
                    Duration::from_secs(5),
                ) {
                    Ok(_) => debug!("dispatched jwks call"),
                    Err(e) => warn!("error dispatching jwks call: {:?}", e),
                }
            }
            OIDCRootMode::Ready => {

                // If this state is reached, the plugin was ready and needs to reload the configuration.
                // This is done by setting the mode to `LoadingConfig` again.
                self.mode = OIDCRootMode::LoadingConfig;
                self.set_tick_period(Duration::from_millis(500));

            }
        }
    }

    /// Creates the http context with the information from the root context and the plugin configuration.
    /// This is called whenever a new http context is created by the proxy.
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        info!("Creating http context with root context information.");

        // Check if the root context is ready.
        if self.mode != OIDCRootMode::Ready {
            warn!("Http context is not ready yet.");
            return None;
        }

        // Create the filter config with information from the root context and the plugin configuration.
        let filter_config = FilterConfig {
            // The Cookie name is the retrieved from the plugin configuration.
            cookie_name: self.plugin_config.as_ref().unwrap().cookie_name.clone(),
            // The cookie duration is retrieved from the plugin configuration.
            cookie_duration: self.plugin_config.as_ref().unwrap().cookie_duration.clone(),

            // The auth endpoint is retrieved from the root context.
            auth_endpoint: self.auth_endpoint.clone().unwrap(),
            // The redirect uri is retrieved from the plugin configuration.
            redirect_uri: Url::parse(self.plugin_config.as_ref().unwrap().redirect_uri.as_str())
                .unwrap(),
            // The client id is retrieved from the plugin configuration.
            client_id: self.plugin_config.as_ref().unwrap().client_id.clone(),
            // The scope is retrieved from the plugin configuration.
            scope: self.plugin_config.as_ref().unwrap().scope.clone(),
            // The claims are retrieved from the plugin configuration.
            claims: self.plugin_config.as_ref().unwrap().claims.clone(),

            // The call back path is retrieved from the plugin configuration.
            call_back_path: self.plugin_config.as_ref().unwrap().call_back_path.clone(),
            // The token endpoint is retrieved from the root context.
            token_endpoint: self.token_endpoint.clone().unwrap(),
            // The authority is retrieved from the plugin configuration.
            authority: self.plugin_config.as_ref().unwrap().authority.clone(),
            // The client secret is retrieved from the plugin configuration.
            client_secret: self.plugin_config.as_ref().unwrap().client_secret.clone(),
            // The audience is retrieved from the plugin configuration.
            audience: self.plugin_config.as_ref().unwrap().audience.clone(),
            // The issuer is retrieved from the root context.
            issuer: self.issuer.to_owned().unwrap(),

            // The public key is retrieved from the root context.
            public_key: self.public_key.as_ref().unwrap().clone(),
        };

        // Return the http context.
        return Some(Box::new(OIDCFlow {
            config: filter_config,
        }));
    }

    fn get_type(&self) -> Option<proxy_wasm::types::ContextType> {
        Some(ContextType::HttpContext)
    }
}

/// The context is used to process the response from the OIDC config endpoint and the jwks endpoint.
/// It also utilised the mode enum to determine what to do with the response.
/// 1. If the mode is `LoadingConfig`, the open id configuration is expected.
/// 2. If the mode is `LoadingJwks`, the jwks endpoint is expected.
/// `Ready` is not expected, as the root context doesn't dispatch any calls in that mode.
impl Context for OIDCRoot {
    fn on_http_call_response(
        &mut self,
        _token_id: u32,
        _num_headers: usize,
        _body_size: usize,
        _num_trailers: usize,
    ) {
        // If the configuration is not yet loaded, try to load it.
        match self.mode {
            OIDCRootMode::LoadingConfig => {
                debug!("loading from openid config endpoint");

                // Output body
                let body = self.get_http_call_response_body(0, _body_size).unwrap();

                // Parse body
                match serde_json::from_slice::<serde_json::Value>(&body) {
                    Ok(parsed) => {
                        debug!("parsed config response: {:?}", parsed);

                        // Extract the required fields from the parsed json.
                        let auth_endpoint = parsed["authorization_endpoint"].as_str().unwrap().to_owned();
                        let token_endpoint = parsed["token_endpoint"].as_str().unwrap().to_owned();
                        let issuer = parsed["issuer"].as_str().unwrap().to_owned();
                        let jwks_uri = parsed["jwks_uri"].as_str().unwrap().to_owned();

                        // Set the root context variables.
                        self.auth_endpoint = Some(Url::parse(&auth_endpoint).unwrap());
                        self.token_endpoint = Some(Url::parse(&token_endpoint).unwrap());
                        self.issuer = Some(issuer);
                        self.jwks_uri = Some(Url::parse(&jwks_uri).unwrap());

                        // Set the mode to loading jwks.
                        self.mode = OIDCRootMode::LoadingJwks;
                    }
                    Err(e) => {
                        warn!("error parsing config response: {:?}", e);
                    }
                }

                // If the configuration is loaded, try to load the jwks.
            }
            OIDCRootMode::LoadingJwks => {
                debug!("loading jwks");

                // Output body
                let body = self.get_http_call_response_body(0, _body_size).unwrap();

                // Parse body
                match serde_json::from_slice::<serde_json::Value>(&body) {
                    Ok(parsed) => {
                        debug!("parsed jwks body: {:?}", parsed);

                        // Extract public key components
                        let public_key_comp_n = parsed["keys"][0]["n"].as_str().unwrap().to_owned();
                        let public_key_comp_e = parsed["keys"][0]["e"].as_str().unwrap().to_owned();

                        // Decode and parse the public key
                        let n_dec = base64engine_urlsafe.decode(public_key_comp_n).unwrap();
                        let e_dec = base64engine_urlsafe.decode(public_key_comp_e).unwrap();
                        let public_key =
                            jwt_simple::algorithms::RS256PublicKey::from_components(&n_dec, &e_dec)
                                .unwrap();

                        // Save the public key to the filter config
                        self.public_key = Some(public_key);

                        // Set the mode to ready and tick again in the configured interval.
                        self.mode = OIDCRootMode::Ready;
                        self.set_tick_period(Duration::from_secs(self.plugin_config.as_ref().unwrap().reload_interval_in_h * 60 * 60));

                        info!("All configuration loaded. Filter is ready. Refreshing config in {} hours. ", self.plugin_config.as_ref().unwrap().reload_interval_in_h);

                    }
                    Err(e) => warn!("error parsing jwks body: {:?}", e),
                }
            }
            OIDCRootMode::Ready => {
                warn!("ready mode is not expected here");
            }
        }
    }
}
