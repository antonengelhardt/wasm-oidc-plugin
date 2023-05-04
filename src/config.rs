use url::{Url};

#[derive(Clone, Debug)]
pub struct FilterConfig {

    // Cookie name
    pub cookie_name: String,

    // Everything relevant for the Code Flow
    pub auth_endpoint: Url,
    pub redirect_uri: Url,
    pub response_type: String,
    pub client_id: String,
    pub scope: String,
    pub claims: String,

    // Everything relevant for the Token Exchange Flow
    pub token_endpoint: Url,
    pub grant_type: String,
    pub client_secret: String,
    pub audience: String,
    pub issuer: String,
}

impl FilterConfig {
    pub fn _new(
        cookie_name: String,
        auth_endpoint: Url,
        redirect_uri: Url,
        response_type: String,
        client_id: String,
        scope: String,
        claims: String,
        token_endpoint: Url,
        grant_type: String,
        client_secret: String,
        audience: String,
        issuer: String,
    ) -> Self {
        Self {
            cookie_name,
            auth_endpoint,
            redirect_uri,
            response_type,
            client_id,
            scope,
            claims,
            token_endpoint,
            grant_type,
            client_secret,
            audience,
            issuer,
        }
    }
}
