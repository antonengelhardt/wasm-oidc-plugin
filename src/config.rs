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
pub struct V2PluginConfiguration {
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
    pub cookie_duration_in_s: u64,
    /// Option to skip Token Validation
    pub token_validation: bool,
    /// AES Key
    #[serde(deserialize_with = "deserialize_aes_key")]
    pub aes_key: Secret<Aes256Gcm>,

    // OpenID Connect Configuration
    /// Reload interval in hours
    pub reload_interval_in_h: u64,
    /// The interval in milliseconds that the plugin will wait for the discovery endpoint to respond or send a new request.
    pub ticking_interval_in_ms: u64,
    /// A list of OpenID Connect configurations that will be used for the filter
    pub open_id_configs: Vec<OpenIdConfig>,
}

impl V2PluginConfiguration {
    pub fn parse(config_bytes: &[u8]) -> anyhow::Result<(Self, bool)> {
        // Try to parse as new format first
        if let Ok(config) = serde_yaml::from_slice::<Self>(config_bytes) {
            config.validate()?;
            return Ok((config, false));
        }

        // If new format fails, try legacy format
        match serde_yaml::from_slice::<V1PluginConfiguration>(config_bytes) {
            Ok(legacy_config) => {
                let config = legacy_config.to_new_format()?;
                config.validate()?;
                Ok((config, true))
            }
            Err(e) => {
                anyhow::bail!(
                    "Failed to parse configuration in both new and legacy formats. Last error: {}",
                    e
                )
            }
        }
    }

    /// Evaluate the plugin configuration and check if the values are valid.
    /// Type checking is done by serde, so we only need to check the values.
    fn validate(&self) -> anyhow::Result<()> {
        ensure!(self.reload_interval_in_h > 0, "`reload_interval` is 0");
        ensure!(self.ticking_interval_in_ms > 0, "`ticking_interval` is 0");
        ensure!(
            self.cookie_name.len() <= 32,
            "`cookie_name` is too long, max 32"
        );

        let cookies_name_regex = Regex::new(r"^[\w\d-]+$").unwrap();
        ensure!(cookies_name_regex.is_match(&self.cookie_name), "`cookie_name` is empty or not valid meaning that it contains invalid characters like ;, =, :, /, space");

        ensure!(!self.logout_path.is_empty(), "`logout_path` is empty");
        ensure!(
            self.logout_path.starts_with('/'),
            "`logout_path` does not start with a `/`"
        );
        ensure!(self.cookie_duration_in_s > 0, "`cookie_duration_in_s` is 0");

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

/// Default value for logout_path in legacy configs
fn default_logout_path() -> Option<String> {
    Some("/logout".to_string())
}

/// Legacy configuration structure for backwards compatibility.
/// This represents the old flat configuration format that only supported a single provider.
#[derive(Clone, Debug, Deserialize)]
struct V1PluginConfiguration {
    // OpenID Connect Configuration (flat structure - single provider only)
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
    pub access_token_header_name: Option<String>,
    /// Prefix for the access token header.
    pub access_token_header_prefix: Option<String>,
    /// The header name that will be used for the id token.
    pub id_token_header_name: Option<String>,
    /// Prefix for the id token header.
    pub id_token_header_prefix: Option<String>,

    // Cookie settings
    /// The cookie name that will be used for the session cookie
    pub cookie_name: String,
    /// The URL to logout the user (optional in legacy format, defaults to "/logout")
    #[serde(default = "default_logout_path")]
    pub logout_path: Option<String>,
    /// Filter out the cookies created and controlled by the plugin
    pub filter_plugin_cookies: bool,
    /// The cookie duration in seconds
    pub cookie_duration: u64,
    /// Option to skip Token Validation
    pub token_validation: bool,
    /// AES Key
    #[serde(deserialize_with = "deserialize_aes_key")]
    pub aes_key: Secret<Aes256Gcm>,

    // Single provider fields (legacy)
    /// The authority that will be used for the dispatch calls
    pub authority: String,
    /// The redirect uri that the authorization endpoint will redirect to and provide the code
    pub redirect_uri: Url,
    /// The client id
    pub client_id: String,
    /// The scope
    pub scope: String,
    /// The claims (as a JSON string in the legacy format)
    pub claims: String,
    /// The client secret
    pub client_secret: Secret<String>,
    /// The audience
    pub audience: String,
}

impl V1PluginConfiguration {
    /// Convert legacy configuration to new multi-provider format
    #[allow(clippy::wrong_self_convention)]
    fn to_new_format(self) -> anyhow::Result<V2PluginConfiguration> {
        // Parse the claims JSON string
        let claims: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&self.claims)
            .map_err(|e| anyhow::anyhow!("Failed to parse claims JSON in legacy config: {}", e))?;

        // Create a default placeholder image URL
        let default_image = Url::parse(
            "https://developers.elementor.com/docs/assets/img/elementor-placeholder-image.png",
        )
        .expect("Default placeholder URL should be valid");

        // Create a single OpenIdConfig from the legacy flat structure
        let open_id_config = OpenIdConfig {
            name: "legacy-provider".to_string(),
            image: default_image,
            config_endpoint: self.config_endpoint,
            upstream_cluster: "oidc".to_string(),
            authority: self.authority,
            redirect_uri: self.redirect_uri,
            client_id: self.client_id,
            scope: self.scope,
            claims,
            client_secret: self.client_secret,
            audience: self.audience,
        };

        // Construct the new PluginConfiguration with the legacy provider as a single entry
        Ok(V2PluginConfiguration {
            open_id_configs: vec![open_id_config],
            reload_interval_in_h: self.reload_interval_in_h,
            ticking_interval_in_ms: 500, // Default value for legacy configs
            exclude_hosts: self.exclude_hosts,
            exclude_paths: self.exclude_paths,
            exclude_urls: self.exclude_urls,
            access_token_header_name: self.access_token_header_name,
            access_token_header_prefix: self.access_token_header_prefix,
            id_token_header_name: self.id_token_header_name,
            id_token_header_prefix: self.id_token_header_prefix,
            cookie_name: self.cookie_name,
            logout_path: self.logout_path.unwrap_or_else(|| "/logout".to_string()),
            filter_plugin_cookies: self.filter_plugin_cookies,
            cookie_duration_in_s: self.cookie_duration,
            token_validation: self.token_validation,
            aes_key: self.aes_key,
        })
    }
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
