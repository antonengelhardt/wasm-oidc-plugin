// serde
use serde::Deserialize;

// serde_regex
use regex::Regex;

// url
use url::Url;

// crate
use crate::responses::SigningKey;

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
    pub public_keys: Vec<SigningKey>,
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

    // Header forwarding settings
    /// Forward the access token in a header
    pub forward_access_token: bool,
    /// The header name that will be used for the access token
    /// If the header name is empty, the access token will be forwarded in the authorization header
    pub access_token_header_name: String,
    /// Prefix for the access token header
    /// If the prefix is empty, the access token will be forwarded without a prefix
    pub access_token_header_prefix: String,
    /// Forward the id token in a header
    pub forward_id_token: bool,
    /// The header name that will be used for the id token
    /// If the header name is empty, the id token will be forwarded in X-Id-Token header
    pub id_token_header_name: String,
    /// Prefix for the id token header
    /// If the prefix is empty, the id token will be forwarded without a prefix
    pub id_token_header_prefix: String,

    // Cookie settings
    /// The cookie name that will be used for the session cookie
    pub cookie_name: String,
    /// The cookie duration in seconds
    pub cookie_duration: u64,
    /// Option to skip Token Validation
    pub token_validation: bool,
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
