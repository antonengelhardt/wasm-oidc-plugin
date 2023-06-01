// proxy-wasm
use proxy_wasm::traits::*;

// log
use log::{info, warn};

// url
use url::Url;

// duration
use std::time::Duration;

// crate
use crate::{FilterConfig, OIDCFlow};

pub struct OIDCRoot {
    /// The Config endpoint
    pub config_endpoint: Option<Url>,
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
    /// Called when the VM is created, allowing the plugin to load configuration.
    fn on_vm_start(&mut self, _vm_configuration_size: usize) -> bool {
        info!("on_vm_start");

        // TODO: Load configuration from VM configuration.
        // let vm_config = self.get_plugin_configuration();

        // Start ticking every 2 seconds.
        self.set_tick_period(Duration::from_secs(2));

        true
    }

    fn on_tick(&mut self) {
        info!("tick");

        // If the configuration is not yet loaded, try to load it.
        match self.mode {
            OIDCRootMode::LoadingConfig => {
                match self.dispatch_http_call(
                    "oidc",
                    vec![
                        (":method", "GET"),
                        (":path", self.config_endpoint.as_ref().unwrap().as_str()),
                        (":authority", "auth.k8s.wwu.de"),
                    ],
                    None,
                    vec![],
                    Duration::from_secs(5),
                ) {
                    Ok(_) => info!("dispatched openid config call"),
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
                        (":path", &jwks_uri),
                        (":method", "GET"),
                        (":authority", "auth.k8s.wwu.de"),
                    ],
                    None,
                    vec![],
                    Duration::from_secs(5),
                ) {
                    Ok(_) => info!("dispatched jwks call"),
                    Err(e) => warn!("error dispatching jwks call: {:?}", e),
                }
            }
            OIDCRootMode::Ready => {
                // If the configuration is loaded, create the http context.
                info!("All configuration loaded. Creating http context.");

                info!("PRINTING CONFIGURATION");
                info!("auth_endpoint: {:?}", self.auth_endpoint);
                info!("token_endpoint: {:?}", self.token_endpoint);
                info!("issuer: {:?}", self.issuer);
                info!("jwks_uri: {:?}", self.jwks_uri);
                info!("public_key_comp_n: {:?}", self.public_key_comp_n);
                info!("public_key_comp_e: {:?}", self.public_key_comp_e);

                // TODO: Set the http context for each request. Not working yet.

                // Set the http context.
                self.create_http_context(0);
                self.set_tick_period(Duration::from_secs(0));

                // Close the root context.
                self.done();
            }
        }
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        info!("creating http context");

        Some(Box::new(OIDCFlow {
            config: FilterConfig {
                cookie_name: "oidcSession".to_string(),
                cookie_duration: 3600,

                auth_endpoint: self.auth_endpoint.clone().unwrap(),
                redirect_uri: Url::parse("http://localhost:10000/oidc/callback").unwrap(),
                client_id: "wasm-oidc-plugin".to_string(),
                scope: "openid email".to_string(),
                claims: r#"{"id_token":{"username":null,"groups":null}}"#.to_owned(),
                call_back_path: "/oidc/callback".to_string(),

                token_endpoint: self.token_endpoint.clone().unwrap(),
                client_secret: "redacted".to_string(),
                audience: "wasm-oidc-plugin".to_string(),
                issuer: self.issuer.to_owned(),

                public_key_comp_n: self.public_key_comp_n.clone().unwrap(),
                public_key_comp_e: self.public_key_comp_e.clone().unwrap(),
            },
        }))
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
            info!("loading config");

            // Output body
            let body = self.get_http_call_response_body(0, _body_size).unwrap();

            // Parse body
            match serde_json::from_slice::<serde_json::Value>(&body) {
                Ok(parsed) => {
                    info!("parsed config response: {:?}", parsed);

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
            info!("loading jwks");

            // Output body
            let body = self.get_http_call_response_body(0, _body_size).unwrap();

            // Parse body
            match serde_json::from_slice::<serde_json::Value>(&body) {
                Ok(parsed) => {
                    info!("parsed jwks body: {:?}", parsed);

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
