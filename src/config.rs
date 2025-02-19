// aes_gcm
use aes_gcm::{Aes256Gcm, KeyInit};
use jwt_simple::reexports::anyhow::{self, ensure};

// core
use core::fmt;

// sec
use sec::Secret;

// std
use std::fmt::Debug;

// serde
use serde::{Deserialize, Deserializer};

// serde_regex
use regex::Regex;

// url
use url::Url;

/// Struct that holds the configuration for the plugin. It is loaded from the config file `envoy.yaml`
#[derive(Clone, Debug, Deserialize)]
pub struct PluginConfiguration {
    // OpenID Connect Configuration
    /// A list of OpenID Connect configurations that will be used for the filter
    pub open_id_configs: Vec<OpenIdConfig>,
    /// Reload interval in hours
    pub reload_interval_in_h: u64,
    /// The interval in milliseconds that the plugin will wait for the discovery endpoint to respond or send a new request.
    pub ticking_interval_in_ms: u64,

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
    /// The URL to logout the user
    pub logout_path: String,
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
}

impl PluginConfiguration {
    pub fn parse(config_bytes: &[u8]) -> anyhow::Result<Self> {
        let config = serde_yaml::from_slice::<Self>(config_bytes)?;
        config.validate()?;
        Ok(config)
    }

    /// Evaluate the plugin configuration and check if the values are valid.
    /// Type checking is done by serde, so we only need to check the values.
    fn validate(&self) -> anyhow::Result<()> {
        ensure!(self.reload_interval_in_h > 0, "`reload_interval` is 0");
        ensure!(
            self.cookie_name.len() <= 32,
            "`cookie_name` is too long, max 32"
        );

        let cookies_name_regex = Regex::new(r"[\w\d-]+").unwrap();
        ensure!(cookies_name_regex.is_match(&self.cookie_name), "`cookie_name` is empty or not valid meaning that it contains invalid characters like ;, =, :, /, space");

        ensure!(!self.logout_path.is_empty(), "`logout_path` is empty");
        ensure!(
            self.logout_path.starts_with('/'),
            "`logout_path` does not start with a `/`"
        );
        ensure!(self.cookie_duration > 0, "`cookie_duration` is 0");

        for provider in &self.open_id_configs {
            ensure!(!provider.authority.is_empty(), "`authority` is empty");
            ensure!(!provider.client_id.is_empty(), "`client_id` is empty");
            ensure!(!provider.scope.is_empty(), "`scope` is empty");
            ensure!(
                !provider.client_secret.reveal().is_empty(),
                "`client_secret` is empty"
            );
            ensure!(!provider.audience.is_empty(), "audience is empty");
        }

        Ok(())
    }
}

/// Struct that holds the configuration for the OpenID Connect provider
#[derive(Clone, Debug, Deserialize)]
pub struct OpenIdConfig {
    // Metadata
    /// Name of the OpenID Connect Provider
    pub name: String,
    /// Image of the OpenID Connect Provider, will be shown in the screen where the user can select the provider
    pub image: Url,

    // Everything relevant for the Code Flow
    /// Config endpoint for the plugin.
    pub config_endpoint: Url,
    /// Upstream Cluster name
    pub upstream_cluster: String,
    /// The authority that will be used for the dispatch calls
    pub authority: String,
    /// The redirect uri that the authorization endpoint will redirect to and provide the code
    pub redirect_uri: Url,
    /// The client id
    pub client_id: String,
    /// The scope
    pub scope: String,
    /// The claims
    pub claims: serde_json::Map<String, serde_json::Value>,

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
