// serde
use serde::Deserialize;

// url
use url::{Url};

/// Struct that holds the configuration for the filter
#[derive(Clone, Debug)]
pub struct FilterConfig {

    // Cookie settings
    /// Name of the cookie that will be used to store the access token
    pub cookie_name: String,
    /// Duration in seconds
    pub cookie_duration: u64,

    // Everything relevant for the Code Flow
    /// The URL of the authorization endpoint
    pub auth_endpoint: Url,
    /// The URL to which the user will be redirected after successful authentication
    pub redirect_uri: Url,
    /// The client ID that will be used for the authentication request
    pub client_id: String,
    /// The scope that will be used for the authentication request
    pub scope: String,
    /// The claims that will be used for the authentication request
    pub claims: String,
    /// The path that will be used for the callback
    pub call_back_path: String,

    // Everything relevant for the Token Exchange Flow
    /// The URL of the token endpoint
    pub token_endpoint: Url,
    /// Authority
    pub authority: String,
    /// The client secret that will be used for the token request
    pub client_secret: String,
    /// The audience that will be used for the token request
    pub audience: String,
    /// The issuer that will be used for the token request
    pub issuer: String,

    // Relevant for Validation of the ID Token
    /// The public key that will be used for the validation of the ID Token
    pub public_key: jwt_simple::algorithms::RS256PublicKey,
}

impl FilterConfig {
    /// Creates a new FilterConfig
    pub fn _new(
        cookie_name: String,
        cookie_duration: u64,
        auth_endpoint: Url,
        redirect_uri: Url,
        client_id: String,
        scope: String,
        claims: String,
        call_back_path: String,
        token_endpoint: Url,
        authority: String,
        client_secret: String,
        audience: String,
        issuer: String,
        public_key: jwt_simple::algorithms::RS256PublicKey,
    ) -> Self {
        Self {
            cookie_name,
            cookie_duration,
            auth_endpoint,
            redirect_uri,
            client_id,
            scope,
            claims,
            call_back_path,
            token_endpoint,
            authority,
            client_secret,
            audience,
            issuer,
            public_key
        }
    }
}

/// Struct that holds the configuration for the plugin
#[derive(Clone, Debug, Deserialize)]
pub struct PluginConfiguration {

    /// Config endpoint for the plugin. It must include the jwks_uri otherwise the plugin will not work
    pub config_endpoint: String,
    /// Reload interval
    pub reload_interval_in_h: u64,

    // Cookie settings
    /// The cookie name
    pub cookie_name: String,
    /// The cookie duration
    pub cookie_duration: u64,

    // Everything relevant for the Code Flow
    /// The authority
    pub authority: String,
    /// The redirect uri
    pub redirect_uri: String,
    /// The client id
    pub client_id: String,
    /// The scope
    pub scope: String,
    /// The claims
    pub claims: String,

    // Everything relevant for the Token Exchange Flow
    /// Call back path
    pub call_back_path: String,
    /// The client secret
    pub client_secret: String,
    /// The audience
    pub audience: String,
}

/// Implementation of the PluginConfiguration
impl PluginConfiguration {
    /// Creates a new PluginConfiguration
    pub fn _new(
        config_endpoint: String,
        reload_interval_in_h: u64,
        cookie_name: String,
        cookie_duration: u64,
        authority: String,
        redirect_uri: String,
        client_id: String,
        scope: String,
        claims: String,
        call_back_path: String,
        client_secret: String,
        audience: String,
    ) -> Self {
        Self {
            config_endpoint,
            reload_interval_in_h,
            cookie_name,
            cookie_duration,
            authority,
            redirect_uri,
            client_id,
            scope,
            claims,
            call_back_path,
            client_secret,
            audience,
        }
    }
}
