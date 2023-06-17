// serde
use serde::Deserialize;

// url
use url::{Url};

/// Struct that holds the configuration for the filter and all relevant information for the
/// OpenID Connect Flow.
#[derive(Clone, Debug)]
pub struct OpenIdConfig {

    // Everything relevant for the Code Flow
    /// The URL of the authorization endpoint
    pub auth_endpoint: Url,

    // Everything relevant for the Token Exchange Flow
    /// The URL of the token endpoint
    pub token_endpoint: Url,
    /// The issuer that will be used for the token request
    pub issuer: String,

    // Relevant for Validation of the ID Token
    /// The public keys that will be used for the validation of the ID Token
    pub public_keys: Vec<jwt_simple::algorithms::RS256PublicKey>,
}

impl OpenIdConfig {
    /// Creates a new FilterConfig
    pub fn _new(
        auth_endpoint: Url,
        token_endpoint: Url,
        issuer: String,
        public_key: Vec<jwt_simple::algorithms::RS256PublicKey>,
    ) -> Self {
        Self {
            auth_endpoint,
            token_endpoint,
            issuer,
            public_keys: public_key
        }
    }
}

/// Struct that holds the configuration for the plugin. It is loaded from the config file
/// `envoy.yaml`
#[derive(Clone, Debug, Deserialize)]
pub struct PluginConfiguration {

    /// Config endpoint for the plugin.
    pub config_endpoint: String,
    /// Reload interval in hours
    pub reload_interval_in_h: u64,
    /// Exclude hosts. Example: localhost:10000
    pub exclude_hosts: Vec<String>,
    /// Exclude paths. Example: /health
    pub exclude_paths: Vec<String>,
    /// Exclude urls. Example: localhost:10000/health
    pub exclude_urls: Vec<String>,

    // Cookie settings
    /// The cookie name that will be used for the session cookie
    pub cookie_name: String,
    /// The cookie duration in seconds
    pub cookie_duration: u64,

    // Everything relevant for the Code Flow
    /// The authority that will be used for the dispatch calls
    pub authority: String,
    /// The redirect uri that the authorization endpoint will redirect to and provide the code
    pub redirect_uri: String,
    /// The client id
    pub client_id: String,
    /// The scope
    pub scope: String,
    /// The claims
    pub claims: String,

    // Everything relevant for the Token Exchange Flow
    /// The client secret
    pub client_secret: String,
    /// The audience. Sometimes its the same as the client id
    pub audience: String,
}

/// Implementation of the PluginConfiguration
impl PluginConfiguration {
    /// Creates a new PluginConfiguration
    pub fn _new(
        config_endpoint: String,
        reload_interval_in_h: u64,
        exclude_hosts: Vec<String>,
        exclude_paths: Vec<String>,
        exclude_urls: Vec<String>,
        cookie_name: String,
        cookie_duration: u64,
        authority: String,
        redirect_uri: String,
        client_id: String,
        scope: String,
        claims: String,
        client_secret: String,
        audience: String,
    ) -> Self {
        Self {
            config_endpoint,
            reload_interval_in_h,
            exclude_hosts,
            exclude_paths,
            exclude_urls,
            cookie_name,
            cookie_duration,
            authority,
            redirect_uri,
            client_id,
            scope,
            claims,
            client_secret,
            audience,
        }
    }
}
