// arc
use std::sync::{Arc, Mutex};

// duration
use std::time::Duration;

// log
use log::{debug, error, info, warn};

// proxy-wasm
use proxy_wasm::{hostcalls, traits::*, types::*};

// std
use std::fmt;

// url
use url::Url;

// crate
use crate::auth::ConfiguredOidc;
use crate::config::{OpenIdConfig, PluginConfiguration};
use crate::pause::PauseRequests;
use crate::responses::{JWKsResponse, OpenIdDiscoveryResponse, SigningKey};

/// This is the main context which loads and parses the plugin configuration, handles the discovery of all
/// Open ID Providers and creates the HTTP Contexts.
pub struct Root {
    /// Plugin config loaded from the envoy configuration
    pub plugin_config: Option<Arc<PluginConfiguration>>,
    /// A set of Open ID Resolvers which are used to load the configuration from the discovery endpoint
    pub open_id_resolvers: Vec<OpenIdResolver>,
    /// A set of Open ID Providers which are used to store the configuration from the discovery endpoint
    pub open_id_providers: Vec<OpenIdProvider>,
    /// Queue of waiting requests which are waiting for the configuration to be loaded
    pub waiting: Mutex<Vec<u32>>,
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

impl fmt::Display for OpenIdResolverState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenIdResolverState::LoadingConfig => write!(f, "LoadingConfig"),
            OpenIdResolverState::LoadingJwks { .. } => write!(f, "LoadingJwks"),
            OpenIdResolverState::Ready => write!(f, "Ready"),
        }
    }
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
    /// The URL of the end session endpoint
    pub end_session_endpoint: Option<Url>,
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
        if let Some(config_bytes) = self.get_plugin_configuration() {
            debug!("got plugin configuration");

            let plugin_config = match PluginConfiguration::parse(&config_bytes) {
                Ok(config) => config,
                Err(e) => {
                    error!("plugin configuration is invalid: {e}");
                    return false;
                }
            };

            self.plugin_config = Some(Arc::new(plugin_config.clone()));

            // Create a new resolver for each open id provider in the plugin configuration.
            let mut resolvers = vec![];
            for open_id_config in plugin_config.open_id_configs.clone() {
                info!(
                    "creating resolver for open id config: {:?}",
                    open_id_config.name
                );

                // Advance to the next state and store the plugin configuration.
                let open_id_resolver = OpenIdResolver {
                    state: OpenIdResolverState::LoadingConfig,
                    open_id_config,
                    token_ids: vec![],
                };
                resolvers.push(open_id_resolver);
            }
            self.open_id_resolvers = resolvers;

            // Tick immediately to load the configuration.
            // See `on_tick` for more information.
            self.set_tick_period(Duration::from_millis(1));

            true
        } else {
            error!("no plugin configuration");
            false
        }
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
                    open_id_providers: self.open_id_providers.clone(),
                    plugin_config: self.plugin_config.clone()?,
                    token_id: None,
                    request_id: "no x-request-id header".to_owned(),
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

    /// The root context is ticking every the configured interval (x) as long as the configuration is not loaded yet.
    ///
    /// On every tick, the plugin is checking if the discovery is active. If the discovery is not active,
    /// the plugin is starting the discovery (as it has been waiting for `reload_interval_in_h` * 3600).
    /// The discovery is started by setting the discovery active to true and setting the state of all resolvers
    /// to `LoadingConfig`. The ticking period is set to x ms to not overload the openid configuration endpoint (x is
    /// the configured interval).
    ///
    /// If the discovery is active, the plugin is checking if all resolvers are in `Ready` state. If all resolvers
    /// are in `Ready` state, the plugin is resuming all requests that were sent during the loading phase. The
    /// discovery is switched to false and the ticking period is set to the configured interval.
    ///
    /// If the discovery is active and not all resolvers are in `Ready` state, the plugin is making a call to the
    /// openid configuration endpoint or the jwks endpoint depending on the state of the resolver.
    fn on_tick(&mut self) {
        debug!("tick");
        // Discovery is not active, start discovery
        if !self.discovery_active {
            info!("discovery is not active, starting discovery");

            // Set discovery to active and set the state of all resolvers to `LoadingConfig`.
            self.discovery_active = true;
            for resolver in self.open_id_resolvers.iter_mut() {
                resolver.state = OpenIdResolverState::LoadingConfig;
            }
            // Tick every x ms to not overload the openid configuration endpoint. x is the configured interval.
            self.set_tick_period(Duration::from_millis(
                self.plugin_config.as_ref().unwrap().ticking_interval_in_ms,
            ));
        }

        // If all providers are in `Ready` state, any request that was sent during the loading phase,
        // is now resumed. Also, the discovery is switched and the ticking period if set to the
        // configured interval.
        let all_resolvers_done = self
            .open_id_resolvers
            .iter_mut()
            .all(|r| matches!(r.state, OpenIdResolverState::Ready { .. }));

        if self.discovery_active && all_resolvers_done {
            info!(
                "discovery is done, resuming {} waiting requests",
                self.waiting.lock().unwrap().len()
            );

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

            // Switch discovery to inactive and set the ticking period to the configured interval.
            self.discovery_active = false;
            self.set_tick_period(Duration::from_secs(
                self.plugin_config.as_ref().unwrap().reload_interval_in_h * 3600,
            ));
        }

        // Make call to openid configuration endpoint for all providers whose state is not ready.
        for resolver in self.open_id_resolvers.iter_mut() {
            match &resolver.state {
                OpenIdResolverState::LoadingConfig { .. } => {
                    // Make call to openid configuration endpoint and load configuration
                    // The response is handled in `on_http_call_response`.
                    match hostcalls::dispatch_http_call(
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
                    match hostcalls::dispatch_http_call(
                        &resolver.open_id_config.upstream_cluster,
                        vec![
                            (":method", "GET"),
                            (":path", open_id_response.jwks_uri.path()),
                            (":authority", open_id_response.jwks_uri.host_str().unwrap()),
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
        let body = self.get_http_call_response_body(0, _body_size);

        // Find resolver to update based on toke_id
        let binding = &mut self.open_id_resolvers;
        let resolver_to_update = match binding
            .iter_mut()
            .find(|resolver| resolver.token_ids.contains(&token_id))
        {
            Some(resolver) => resolver,
            None => {
                debug!("no resolver found for token_id: {}", token_id);
                return;
            }
        };

        debug!(
            "token_id {} is for resolver/provider {} in state {}",
            token_id, resolver_to_update.open_id_config.name, resolver_to_update.state
        );

        // Check for each state what to do with the response.
        match &resolver_to_update.state {
            // If the plugin is in Loading `LoadingConfig` state, the response is expected to be the
            // openid configuration.
            OpenIdResolverState::LoadingConfig => {
                // Parse the response body as json.
                let body = match body {
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
                    }
                    Ok(open_id_response) => {
                        debug!("parsed openid config response: {:#?}", open_id_response);

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
                let body = match body {
                    Some(body) => body,
                    None => {
                        warn!("no body in jwks response");
                        return;
                    }
                };

                match serde_json::from_slice::<JWKsResponse>(&body) {
                    Err(e) => {
                        warn!("error parsing jwks body: {:?}", e);
                    }
                    Ok(jwks_response) => {
                        debug!("parsed jwks body: {:#?}", jwks_response);

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
                        let provider = self.open_id_providers.iter_mut().find(|provider| {
                            provider.open_id_config.name == resolver_to_update.open_id_config.name
                        });

                        let new_provider = OpenIdProvider {
                            open_id_config: resolver_to_update.open_id_config.clone(),
                            auth_endpoint: open_id_response.authorization_endpoint.clone(),
                            token_endpoint: open_id_response.token_endpoint.clone(),
                            end_session_endpoint: open_id_response.end_session_endpoint.clone(),
                            issuer: open_id_response.issuer.clone(),
                            public_keys: keys,
                        };

                        if let Some(p) = provider {
                            *p = new_provider;
                        } else {
                            self.open_id_providers.push(new_provider);
                        }

                        resolver_to_update.state = OpenIdResolverState::Ready {};
                        resolver_to_update.token_ids.clear();
                    }
                }
            }

            // If the plugin is in `Ready` state, the response is ignored and the state is not changed.
            OpenIdResolverState::Ready { .. } => {
                warn!("ready state is not expected here");
            }
        }
    }
}
