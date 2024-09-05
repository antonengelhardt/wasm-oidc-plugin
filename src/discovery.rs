// arc
use std::sync::{Arc, Mutex};

// duration
use std::time::Duration;

// log
use log::{debug, info, warn};

// proxy-wasm
use proxy_wasm::{hostcalls, traits::*, types::*};

// regex
use regex::Regex;

// url
use url::Url;

// crate
use crate::config::{OpenIdConfig, PluginConfiguration};
use crate::error::PluginError;
use crate::responses::{JWKsResponse, OpenIdDiscoveryResponse, SigningKey};
use crate::{ConfiguredOidc,PauseRequests};

// This is the initial entry point of the plugin.
proxy_wasm::main! {{

    proxy_wasm::set_log_level(LogLevel::Debug);

    info!("Starting plugin");

    // This sets the root context, which is the first context that is called on startup.
    // The root context is used to initialize the plugin and load the configuration from the
    // plugin config and the discovery endpoints.
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(Root {
        plugin_config: None,
        open_id_providers: Mutex::new(vec![]),
        open_id_resolvers: Mutex::new(vec![]),
        waiting: Mutex::new(Vec::new()),
        discovery_active: false,
    }) });
}}

/// This is the main context which loads and parses the plugin configuration, handles the discovery of all
/// Open ID Providers and creates the HTTP Contexts.
pub struct Root {
    /// Plugin config loaded from the envoy configuration
    pub plugin_config: Option<Arc<PluginConfiguration>>,
    /// A set of Open ID Resolvers which are used to load the configuration from the discovery endpoint
    pub open_id_resolvers: Mutex<Vec<OpenIdResolver>>,
    /// A set of Open ID Providers which are used to store the configuration from the discovery endpoint
    pub open_id_providers: Mutex<Vec<OpenIdProvider>>,
    /// Queue of waiting requests which are waiting for the configuration to be loaded
    waiting: Mutex<Vec<u32>>,
    /// Flag to determine if the discovery is active
    pub discovery_active: bool,
}

#[derive(Debug)]
/// A resolver handles the loading of the configuration from the open id discovery endpoint and the jwks endpoint.
pub struct OpenIdResolver {
    /// The state of the resolver
    pub state: OpenIdResolverState,
    /// The configuration from the plugin configuration
    pub open_id_config: OpenIdConfig,
    /// token_ids of the HttpCalls to verify the call is correct and to determine which response comes in
    token_ids: Vec<u32>,
}

/// The state of the resolver is an enum which has the following variants:
/// - LoadingConfig: The plugin configuration is being loaded
/// - LoadingJwks: The jwks configuration is being loaded
/// - Ready: The plugin is ready
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum OpenIdResolverState {
    /// The root context is loading the configuration from the open id discovery endpoint
    LoadingConfig,
    /// The root context is loading the jwks configuration using the open id configuration
    LoadingJwks {
        /// response from the config endpoint
        open_id_response: Arc<OpenIdDiscoveryResponse>,
    },
    /// The root context is ready
    Ready,
}

/// The OpenIdProvider struct holds all information about the Open ID Provider that is needed for the
/// plugin to work. This includes the Open ID Configuration, the URLs of the endpoints and the public keys
/// that are used for the validation of the ID Token.
#[derive(Clone, Debug)]
pub struct OpenIdProvider {
    pub open_id_config: OpenIdConfig,
    /// The URL of the authorization endpoint
    pub auth_endpoint: Url,
    /// The URL of the token endpoint
    pub token_endpoint: Url,
    /// The issuer that will be used for the token request
    pub issuer: String,
    /// The public keys that will be used for the validation of the ID Token
    pub public_keys: Vec<SigningKey>,
}

/// The root context creates new HTTP Contexts and is responsible for loading the plugin configuration, as
/// well as the discovery of the Open ID Providers.
/// The first step after startup is the loading of the plugin configuration. This is done in the `on_configure`
/// function. The plugin configuration is loaded from the plugin configuration and parsed into the
/// `PluginConfiguration` struct. The configuration is then evaluated and checked if the values are valid.
/// If the configuration is valid, the plugin configuration is stored in the root context and the next state
/// is set. The next state is to load the configuration from the Open ID Providers. This is done by creating
/// a new `OpenIdResolver` for each Open ID Provider in the plugin configuration. The state of the resolver
/// is set to `LoadingConfig` and the configuration is loaded from the Open ID Configuration endpoint. The
/// response is handled in the `on_http_call_response` function. If the response is successful, the state is
/// set to `LoadingJwks` and the jwks endpoint is called. The response is handled in the `on_http_call_response`
/// function. If the response is successful, the state is set to `Ready` and the Open ID Provider is stored in
/// the root context. If all Open ID Providers are in the `Ready` state, the plugin is ready and the waiting
/// requests are resumed.
impl RootContext for Root {
    /// Called when proxy is being configured.
    /// This is where the plugin configuration is loaded and the next state is set.
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        info!("plugin is configuring");

        // Load the configuration from the plugin configuration.
        match self.get_plugin_configuration() {
            None => warn!("no plugin configuration"),
            Some(config_bytes) => {
                debug!("got plugin configuration");

                // Parse the configuration in a yaml format.
                match serde_yaml::from_slice::<PluginConfiguration>(&config_bytes) {
                    Err(e) => warn!("error parsing plugin configuration: {:?}", e),
                    Ok(plugin_config) => {
                        debug!("parsed plugin configuration: {:?}", plugin_config);

                        // Evaluate the plugin configuration and check if the values are valid.
                        // Type checking is done by serde, so we only need to check the values.
                        match Root::evaluate_config(plugin_config.clone()) {
                            Err(e) => {
                                panic!("plugin configuration is invalid: {:?}", e);
                            }
                            Ok(_) => {
                                info!("plugin configuration is valid");
                            }
                        }

                        self.plugin_config = Some(Arc::new(plugin_config.clone()));

                        let mut resolvers = vec![];
                        for provider in plugin_config.open_id_configs.clone() {
                            info!("creating resolver for open id provider: {:?}", provider);

                            // Advance to the next state and store the plugin configuration.
                            let open_id_resolver = OpenIdResolver {
                                state: OpenIdResolverState::LoadingConfig,
                                open_id_config: provider,
                                token_ids: vec![],
                            };
                            resolvers.push(open_id_resolver);
                        }
                        self.open_id_resolvers = Mutex::new(resolvers);

                        // Tick immediately to load the configuration.
                        // See `on_tick` for more information.
                        self.set_tick_period(Duration::from_millis(1));

                        return true;
                    }
                }
            }
        }

        false
    }

    /// Creates the http context with the information from the open_id_providers and the plugin_configuration.
    /// This is called whenever a new http context is created by the proxy.
    /// When the plugin is not yet ready, the http context is created in `PauseRequests` state and the
    /// context id is added to the waiting queue to be processed later.
    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        // Check if all open id providers are ready
        match self.discovery_active {
            // If the plugin is ready, create the http context `ConfiguredOidc` with the root context information.
            false => {
                debug!("creating http context with root context information");

                // Return the http context.
                Some(Box::new(ConfiguredOidc {
                    open_id_providers: Arc::new(self.open_id_providers.lock().unwrap().to_vec()),
                    plugin_config: self.plugin_config.clone()?,
                    token_id: None,
                }))
            }

            // If the plugin is not ready, return the http context in `PauseRequests` state.
            _ => {
                warn!("root context is not ready yet, queueing http context.");

                // Add the context id to the waiting queue.
                self.waiting.lock().unwrap().push(context_id);

                // Return the http context in `Unconfigured` state.
                Some(Box::new(PauseRequests {
                    original_path: None,
                }))
            }
        }
    }

    /// The root context is ticking every 300 millis as long as the configuration is not loaded yet.
    /// On every tick, the plugin is checking if the discovery is active. If the discovery is not active,
    /// the plugin is starting the discovery. The discovery is started by setting the discovery active to true.
    ///
    /// If the discovery is active, the plugin is checking if all resolvers are in `Ready` state. If all resolvers
    /// are in `Ready` state, the plugin is resuming all requests that were sent during the loading phase. The
    /// discovery is switched to false and the ticking period is set to the configured interval.
    /// If the discovery is active and not all resolvers are in `Ready` state, the plugin is making a call to the
    /// openid configuration endpoint or the jwks endpoint depending on the state of the resolver.
    fn on_tick(&mut self) {
        debug!("tick");
        // Discovery is not active, start discovery
        if self.discovery_active == false {
            info!("discovery is not active, starting discovery");

            // Set discovery to active and set the state of all resolvers to `LoadingConfig`.
            self.discovery_active = true;
            for resolver in self.open_id_resolvers.lock().unwrap().iter_mut() {
                resolver.state = OpenIdResolverState::LoadingConfig;
            }
            // Tick every 300ms to not overload the openid configuration endpoint.
            self.set_tick_period(Duration::from_millis(300));
        }

        // If all providers are in `Ready` state, any request that was sent during the loading phase,
        // is now resumed. Also, the discovery is switched and the ticking period if set to the
        // configured interval.
        let all_resolvers_done = self
            .open_id_resolvers
            .lock()
            .unwrap()
            .iter_mut()
            .all(|r| matches!(r.state, OpenIdResolverState::Ready { .. }));

        if self.discovery_active && all_resolvers_done {
            info!("discovery is done, resuming waiting requests");

            // Resume all requests that were sent during the loading phase. See `PauseRequest` for more.
            for context_id in self.waiting.lock().unwrap().drain(..) {
                debug!("resuming queued request with id {}", context_id);
                hostcalls::set_effective_context(context_id).unwrap_or_else(|e| {
                        warn!("error setting effective context, most likely the tab was closed already: {:?}", e);
                    });
                hostcalls::resume_http_request().unwrap_or_else(|e| {
                    warn!(
                        "error resuming http request, most likely the tab was closed already: {:?}",
                        e
                    );
                });
            }

            self.discovery_active = false;
            self.set_tick_period(Duration::from_secs(
                self.plugin_config.as_ref().unwrap().reload_interval_in_h * 3600,
            ));
        }

        // Make call to openid configuration endpoint for all providers whose state is not ready.
        for resolver in self.open_id_resolvers.lock().unwrap().iter_mut() {
            match &resolver.state {
                OpenIdResolverState::LoadingConfig { .. } => {
                    // Make call to openid configuration endpoint and load configuration
                    // The response is handled in `on_http_call_response`.
                    match self.dispatch_http_call(
                        &resolver.open_id_config.upstream_cluster,
                        vec![
                            (":method", "GET"),
                            (":path", resolver.open_id_config.config_endpoint.path()),
                            (":authority", resolver.open_id_config.authority.as_str()),
                        ],
                        None,
                        vec![],
                        Duration::from_secs(5),
                    ) {
                        Err(e) => warn!("error dispatching oidc call: {:?}", e),
                        Ok(id) => {
                            resolver.token_ids.push(id);
                            debug!(
                                "dispatched openid config call to {}, count of unanswered request: {}",
                                resolver.open_id_config.config_endpoint,
                                resolver.token_ids.len()
                            );
                        }
                    }
                }

                // Make call to jwks endpoint for all providers whose state is not ready.
                // The response is handled in `on_http_call_response`.
                OpenIdResolverState::LoadingJwks { open_id_response } => {
                    match self.dispatch_http_call(
                        &resolver.open_id_config.upstream_cluster,
                        vec![
                            (":method", "GET"),
                            (":path", open_id_response.jwks_uri.path()),
                            (":authority", resolver.open_id_config.authority.as_str()),
                        ],
                        None,
                        vec![],
                        Duration::from_secs(5),
                    ) {
                        Err(e) => warn!("error dispatching jwks call: {:?}", e),
                        Ok(id) => {
                            resolver.token_ids.push(id);
                            debug!(
                                "dispatched jwks call to {}, count of unanswered request: {}",
                                open_id_response.jwks_uri,
                                resolver.token_ids.len()
                            );
                        }
                    }
                }
                OpenIdResolverState::Ready {} => {
                    // Clear all token ids as the resolver is ready
                    resolver.token_ids.clear();
                }
            }
        }
    }
    /// This is one of those functions that need to be there for some reason but we are
    /// not sure why. It just doesn't work without it.
    fn get_type(&self) -> Option<proxy_wasm::types::ContextType> {
        Some(ContextType::HttpContext)
    }
}

/// The context processes all responses from the open id config endpoints and jwks endpoints.
impl Context for Root {
    /// Called when the response from any http call (sent from root context) is received.
    fn on_http_call_response(
        &mut self,
        token_id: u32,
        _num_headers: usize,
        _body_size: usize,
        _num_trailers: usize,
    ) {
        debug!("received http call response with token_id: {}", token_id);

        // Find resolver to update based on toke_id
        let mut binding = self.open_id_resolvers.lock().unwrap();
        let resolver_to_update = match binding
            .iter_mut()
            .find(|resolver| resolver.token_ids.contains(&token_id))
        {
            Some(resolver) => resolver,
            None => {
                warn!("no resolver found for token_id: {}", token_id);
                return;
            }
        };

        debug!(
            "token_id {} is for resolver/provider {} in state {:?}",
            token_id, resolver_to_update.open_id_config.name, resolver_to_update.state
        );

        // Check for each state what to do with the response.
        match &resolver_to_update.state {
            // If the plugin is in Loading `LoadingConfig` state, the response is expected to be the
            // openid configuration.
            OpenIdResolverState::LoadingConfig => {
                // Parse the response body as json.
                let body = match self.get_http_call_response_body(0, _body_size) {
                    Some(body) => body,
                    None => {
                        warn!("no body in openid config response");
                        return;
                    }
                };

                // Parse body using serde_json or fail
                match serde_json::from_slice::<OpenIdDiscoveryResponse>(&body) {
                    Err(e) => {
                        warn!(
                            "error parsing config response ({:?}): {:?}",
                            String::from_utf8(body),
                            e,
                        );
                        return;
                    }
                    Ok(open_id_response) => {
                        debug!("parsed openid config response: {:?}", open_id_response);

                        // Set the state to `LoadingJwks`.
                        resolver_to_update.state = OpenIdResolverState::LoadingJwks {
                            open_id_response: Arc::new(open_id_response),
                        };
                        // And clear all token_ids
                        resolver_to_update.token_ids.clear();
                    }
                }
            }

            // If the plugin is in `LoadingJwks` state, the jwks endpoint is expected.
            OpenIdResolverState::LoadingJwks {
                open_id_response, ..
            } => {
                // Parse body using serde_json or fail
                let body = match self.get_http_call_response_body(0, _body_size) {
                    Some(body) => body,
                    None => {
                        warn!("no body in jwks response");
                        return;
                    }
                };

                match serde_json::from_slice::<JWKsResponse>(&body) {
                    Err(e) => {
                        warn!("error parsing jwks body: {:?}", e);
                        // Stay in the same state as the response couldn't be parsed.
                        return;
                    }
                    Ok(jwks_response) => {
                        debug!("parsed jwks body: {:?}", jwks_response);

                        // Check if keys are present
                        if jwks_response.keys.is_empty() {
                            warn!("no keys found in jwks response, retry in 1 minute");
                            // TODO: Hmm??
                            // self.set_tick_period(Duration::from_secs(60));
                            return;
                        }

                        // For all keys, create a signing key if possible
                        let mut keys: Vec<SigningKey> = vec![];
                        for key in jwks_response.keys {
                            // Create the signing key from the JWK
                            let signing_key = SigningKey::from(key);

                            // Add the signing key to the list of keys
                            keys.push(signing_key);
                        }

                        // Find OpenIdProvider to update or create a new one
                        let mut open_id_providers = self.open_id_providers.lock().unwrap();
                        let provider = open_id_providers.iter_mut().find(|provider| {
                            provider.issuer == resolver_to_update.open_id_config.authority
                        });

                        if let Some(p) = provider {
                            p.public_keys = keys;
                        } else {
                            open_id_providers.push(OpenIdProvider {
                                open_id_config: resolver_to_update.open_id_config.clone(),
                                auth_endpoint: open_id_response.authorization_endpoint.clone(),
                                token_endpoint: open_id_response.token_endpoint.clone(),
                                issuer: open_id_response.issuer.clone(),
                                public_keys: keys,
                            });
                        }

                        resolver_to_update.state = OpenIdResolverState::Ready {};
                        resolver_to_update.token_ids.clear();
                    }
                }
            }

            // If the plugin is in `Ready` state, the response is ignored and the state is not changed.
            OpenIdResolverState::Ready { .. } => {
                warn!("ready state is not expected here");
                return;
            }
        };
    }
}

impl Root {
    /// Evaluate the plugin configuration and check if the values are valid.
    /// Type checking is done by serde, so we only need to check the values.
    /// * `plugin_config` - The plugin configuration to be evaluated
    /// Returns `Ok` if the configuration is valid, otherwise `Err` with a message.
    pub fn evaluate_config(plugin_config: PluginConfiguration) -> Result<(), PluginError> {
        // Reload Interval
        if plugin_config.reload_interval_in_h == 0 {
            return Err(PluginError::ConfigError(
                "`reload_interval` is 0".to_string(),
            ));
        }

        // Cookie Name
        if plugin_config.cookie_name.len() > 32 {
            return Err(PluginError::ConfigError(
                "`cookie_name` is too long, max 32".to_string(),
            ));
        }

        let cookies_name_regex = Regex::new(r"[\w\d-]+").unwrap();
        if plugin_config.cookie_name.is_empty()
            || !cookies_name_regex.is_match(&plugin_config.cookie_name)
        {
            return Err(PluginError::ConfigError("`cookie_name` is empty or not valid meaning that it contains invalid characters like ;, =, :, /, space".to_string()));
        }

        // Cookie Duration
        if plugin_config.cookie_duration == 0 {
            return Err(PluginError::ConfigError(
                "`cookie_duration` is 0".to_string(),
            ));
        }

        for open_id_provider in plugin_config.open_id_configs {
            // Authority
            if open_id_provider.authority.is_empty() {
                return Err(PluginError::ConfigError("`authority` is empty".to_string()));
            }

            // Client Id
            if open_id_provider.client_id.is_empty() {
                return Err(PluginError::ConfigError("`client_id` is empty".to_string()));
            }

            // Scope
            if open_id_provider.scope.is_empty() {
                return Err(PluginError::ConfigError("`scope` is empty".to_string()));
            }

            // Claims
            if open_id_provider.claims.is_empty() {
                return Err(PluginError::ConfigError("`claims` is empty".to_string()));
            }

            // Client Secret
            if open_id_provider.client_secret.reveal().is_empty() {
                return Err(PluginError::ConfigError(
                    "client_secret is empty".to_string(),
                ));
            }

            // Audience
            if open_id_provider.audience.is_empty() {
                return Err(PluginError::ConfigError("audience is empty".to_string()));
            }
        }

        // Else return Ok
        Ok(())
    }
}
