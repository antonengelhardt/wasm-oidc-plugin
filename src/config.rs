// serde
use serde::Deserialize;

// serde_regex
use regex::Regex;

// url
use url::Url;

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

/// Struct that holds the configuration for the plugin. It is loaded from the config file
/// `envoy.yaml`
#[derive(Clone, Debug, Deserialize)]
pub struct PluginConfiguration {

    /// Config endpoint for the plugin.
    pub config_endpoint: String,
    /// Reload interval in hours
    pub reload_interval_in_h: u64,
    /// Exclude hosts. Example: localhost:10000
    #[serde(with = "serde_regex")]
    pub exclude_hosts: Vec<Regex>,
    /// Exclude paths. Example: /health
    #[serde(with = "serde_regex")]
    pub exclude_paths: Vec<Regex>,
    /// Exclude urls. Example: localhost:10000/health
    #[serde(with = "serde_regex")]
    pub exclude_urls: Vec<Regex>,

    // Cookie settings
    /// The cookie name that will be used for the session cookie
    pub cookie_name: String,
    /// The cookie duration in seconds
    pub cookie_duration: u64,
    /// AES Key
    pub aes_key: String,

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
