// proxy-wasm
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// log
use log::{info, warn, debug};

// url
use url::Url;

// duration
use std::time::Duration;

// crate
use crate::config::PluginConfiguration;
use crate::{FilterConfig, OIDCFlow};

/// This context is responsible for getting the OIDC configuration and setting the http context.
pub struct OIDCRoot {
    /// Plugin config
    pub plugin_config: Option<PluginConfiguration>,

    /// The authorization endpoint
    pub auth_endpoint: Option<Url>,
    /// The token endpoint
    pub token_endpoint: Option<Url>,
    /// The issuer
    pub issuer: String,
    /// Mode of the root context
    pub mode: OIDCRootMode,
    /// The url from which the public key can be retrieved
    pub jwks_uri: Option<Url>,
    /// The public key modulus
    pub public_key_comp_n: Option<String>,
    /// The public key exponent
    pub public_key_comp_e: Option<String>,
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
    /// Called when the VM is created, allowing to start the ticking of the plugin.
    fn on_vm_start(&mut self, _vm_configuration_size: usize) -> bool {

        info!("VM started");

        // Start ticking every 2 seconds.
        self.set_tick_period(Duration::from_secs(2));

        true
    }

    /// Called when the configuration is loaded.
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        // TODO: Load configuration from plugin configuration such as cookie settings, etc.

        info!("Pluin is configuring");

        // Load the configuration from the plugin configuration.
        match self.get_plugin_configuration() {
            Some(config_bytes) => {
                debug!("got plugin configuration");

                match serde_json::from_slice(&config_bytes) {
                    Ok(parsed) => {
                        debug!("parsed plugin configuration");

                        // Set the plugin configuration.
                        self.plugin_config = Some(parsed);

                        return true;
                    }
                    Err(e) => warn!("error parsing plugin configuration: {:?}", e),
                }
            }
            None => warn!("no plugin configuration"),
        }

        false
    }

    fn on_tick(&mut self) {

        debug!("tick");

        // If the configuration is not yet loaded, try to load it.
        match self.mode {
            OIDCRootMode::LoadingConfig => {
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

                // TODO: Make call to jwks endpoint and load public key
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
                // If the configuration is loaded, create the http context.
                debug!("All configuration loaded. Creating http context.");

                // Set the http context.
                self.create_http_context(0);
                // And stop ticking.
                self.set_tick_period(Duration::from_secs(0));
            }
        }
    }

    /// Creates the http context with the information from the root context and the plugin configuration.
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        info!("Creating http context with root context information.");

        // Create the filter config.
        let filter_config = FilterConfig{
            cookie_name: self.plugin_config.as_ref().unwrap().cookie_name.clone(),
            cookie_duration: self.plugin_config.as_ref().unwrap().cookie_duration.clone(),

            auth_endpoint: self.auth_endpoint.clone().unwrap(),
            redirect_uri: Url::parse(self.plugin_config.as_ref().unwrap().redirect_uri.as_str()).unwrap(),
            client_id: self.plugin_config.as_ref().unwrap().client_id.clone(),
            scope: self.plugin_config.as_ref().unwrap().scope.clone(),
            claims: self.plugin_config.as_ref().unwrap().claims.clone(),

            call_back_path: self.plugin_config.as_ref().unwrap().call_back_path.clone(),
            token_endpoint: self.token_endpoint.clone().unwrap(),
            authority: self.plugin_config.as_ref().unwrap().authority.clone(),
            client_secret: self.plugin_config.as_ref().unwrap().client_secret.clone(),
            audience:self.plugin_config.as_ref().unwrap().audience.clone(),
            issuer: self.issuer.to_owned(),

            public_key_comp_n: self.public_key_comp_n.clone().unwrap(),
            public_key_comp_e: self.public_key_comp_e.clone().unwrap(),
        };

        // Return the http context.
        return Some(Box::new(OIDCFlow{
            config: filter_config,
        }));
    }

    fn get_type(&self) -> Option<proxy_wasm::types::ContextType> {
        Some(ContextType::HttpContext)
    }
}

/// The context is used to process the response from the OIDC config endpoint.
impl Context for OIDCRoot {
    fn on_http_call_response(
        &mut self,
        _token_id: u32,
        _num_headers: usize,
        _body_size: usize,
        _num_trailers: usize,
    ) {
        // If the configuration is not yet loaded, try to load it.
        if self.mode == OIDCRootMode::LoadingConfig {
            debug!("loading config");

            // Output body
            let body = self.get_http_call_response_body(0, _body_size).unwrap();

            // Parse body
            match serde_json::from_slice::<serde_json::Value>(&body) {
                Ok(parsed) => {
                    debug!("parsed config response: {:?}", parsed);

                    let auth_endpoint = parsed["authorization_endpoint"]
                        .as_str()
                        .unwrap()
                        .to_owned();
                    let token_endpoint = parsed["token_endpoint"].as_str().unwrap().to_owned();
                    let issuer = parsed["issuer"].as_str().unwrap().to_owned();
                    let jwks_uri = parsed["jwks_uri"].as_str().unwrap().to_owned();

                    self.auth_endpoint = Some(Url::parse(&auth_endpoint).unwrap());
                    self.token_endpoint = Some(Url::parse(&token_endpoint).unwrap());
                    self.issuer = issuer;
                    self.jwks_uri = Some(Url::parse(&jwks_uri).unwrap());

                    self.mode = OIDCRootMode::LoadingJwks;
                }
                Err(e) => {
                    warn!("error parsing config response: {:?}", e);
                }
            }

        // If the configuration is loaded, try to load the jwks.
        } else if self.mode == OIDCRootMode::LoadingJwks {
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

                    // Give the public key to the filter
                    self.public_key_comp_n = Some(public_key_comp_n);
                    self.public_key_comp_e = Some(public_key_comp_e);

                    self.mode = OIDCRootMode::Ready;
                }
                Err(e) => warn!("error parsing jwks body: {:?}", e),
            }
        }
    }
}
