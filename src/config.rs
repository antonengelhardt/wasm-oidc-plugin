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
    pub call_back_path: String,

    // Everything relevant for the Token Exchange Flow
    pub token_endpoint: Url,
    pub grant_type: String,
    pub client_secret: String,
    pub audience: String,
    pub issuer: String,

    // Relevant for Validation of the ID Token
    pub public_key_comp_n: String,
    pub public_key_comp_e: String,
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
        call_back_path: String,
        token_endpoint: Url,
        grant_type: String,
        client_secret: String,
        audience: String,
        issuer: String,
        public_key_comp_n: String,
        public_key_comp_e: String,
    ) -> Self {
        Self {
            cookie_name,
            auth_endpoint,
            redirect_uri,
            response_type,
            client_id,
            scope,
            claims,
            call_back_path,
            token_endpoint,
            grant_type,
            client_secret,
            audience,
            issuer,
            public_key_comp_n,
            public_key_comp_e,
        }
    }
}

// #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
// pub struct ProviderMetadata {
//     issuer: Url,
//     authorization_endpoint: Url,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     token_endpoint: Option<Url>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     userinfo_endpoint: Option<Url>,
//     jwks_uri: Url,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     scopes_supported: Option<Vec<String>>,
//     response_types_supported: Vec<String>,
//     subject_types_supported: Vec<String>,
//     id_token_signing_alg_values_supported: Vec<String>,
// }

// impl ProviderMetadata
// {
//     pub fn _new(
//         issuer: Url,
//         authorization_endpoint: Url,
//         token_endpoint: Option<Url>,
//         userinfo_endpoint: Option<Url>,
//         jwks_uri: Url,
//         scopes_supported: Option<Vec<String>>,
//         response_types_supported: Vec<String>,
//         subject_types_supported: Vec<String>,
//         id_token_signing_alg_values_supported: Vec<String>,
//     ) -> Self {
//         Self {
//             issuer,
//             authorization_endpoint,
//             token_endpoint,
//             userinfo_endpoint,
//             jwks_uri,
//             scopes_supported,
//             response_types_supported,
//             subject_types_supported,
//             id_token_signing_alg_values_supported,
//         }
//     }

//     pub fn get_issuer(&self) -> &Url {
//         &self.issuer
//     }

//     pub fn get_authorization_endpoint(&self) -> &Url {
//         &self.authorization_endpoint
//     }

//     pub fn get_token_endpoint(&self) -> Option<&Url> {
//         self.token_endpoint.as_ref()
//     }

//     pub fn get_userinfo_endpoint(&self) -> Option<&Url> {
//         self.userinfo_endpoint.as_ref()
//     }

//     pub fn get_jwks_uri(&self) -> &Url {
//         &self.jwks_uri
//     }

//     pub fn from_bytes(bytes: &Vec<u8>) -> Result<ProviderMetadata, Error> {
//         match serde_json::from_slice::<ProviderMetadata>(bytes.as_slice()) {
//             Ok(metadata) => Ok(metadata),
//             Err(e) => Err(e),
//         }

//     }
// }
