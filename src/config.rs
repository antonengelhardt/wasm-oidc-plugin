use core::fmt;
use std::fmt::Debug;

use aes_gcm::{Aes256Gcm, KeyInit};
use sec::Secret;
// serde
use serde::{Deserialize, Deserializer};

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
    pub config_endpoint: Url,
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
    /// The header name that will be used for the access token.
    /// If the header name is empty, the access token will not be forwarded
    pub access_token_header_name: Option<String>,
    /// Prefix for the access token header.
    /// If the prefix is empty, the access token will be forwarded without a prefix
    pub access_token_header_prefix: Option<String>,

    /// The header name that will be used for the id token.
    /// If the header name is empty, the id token will not be forwarded
    pub id_token_header_name: Option<String>,
    /// Prefix for the id token header.
    /// If the prefix is empty, the id token will be forwarded without a prefix
    pub id_token_header_prefix: Option<String>,

    // Cookie settings
    /// The cookie name that will be used for the session cookie
    pub cookie_name: String,
    /// Filter out the cookies created and controlled by the plugin
    /// If the value is true, the cookies will be filtered out
    pub filter_plugin_cookies: bool,
    /// The cookie duration in seconds
    pub cookie_duration: u64,
    /// Option to skip Token Validation
    pub token_validation: bool,
    /// AES Key
    #[serde(deserialize_with = "deserialize_aes_key")]
    pub aes_key: Secret<Aes256Gcm>,

    // Everything relevant for the Code Flow
    /// The authority that will be used for the dispatch calls
    pub authority: String,
    /// The redirect uri that the authorization endpoint will redirect to and provide the code
    pub redirect_uri: Url,
    /// The client id
    pub client_id: String,
    /// The scope
    pub scope: String,
    /// The claims
    pub claims: String,

    // Everything relevant for the Token Exchange Flow
    /// The client secret
    pub client_secret: Secret<String>,
    /// The audience. Sometimes its the same as the client id
    pub audience: String,
}

/// Deserialize a base64 encoded 32 byte AES key
fn deserialize_aes_key<'de, D>(deserializer: D) -> Result<Secret<Aes256Gcm>, D::Error>
where
    D: Deserializer<'de>,
{
    use base64::{engine::general_purpose::STANDARD as base64engine, Engine as _};
    use serde::de::{Error, Visitor};

    struct AesKeyVisitor;

    impl<'de> Visitor<'de> for AesKeyVisitor {
        type Value = Secret<Aes256Gcm>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a base64 string encoding a 32 byte AES key")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            let aes_key = base64engine.decode(s).map_err(Error::custom)?;
            let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| {
                Error::custom(format!("{e}, got {} bytes, expected 32", aes_key.len()))
            })?;

            Ok(Secret::new(cipher))
        }
    }

    // using a visitor here instead of just <&str>::deserialize
    // makes sure that any error message contains the field name
    deserializer.deserialize_str(AesKeyVisitor)
}
