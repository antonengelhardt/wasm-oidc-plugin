// serde
use serde::Deserialize;

/// OpenID Connect Discovery
#[derive(Deserialize, Debug)]
pub struct OidcDiscoveryResponse {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

#[derive(Deserialize, Debug)]
pub struct JWKsResponse {
    pub keys: Vec<JWK>,
}

#[derive(Deserialize, Debug)]
pub struct JWK {
    pub kty: String,
    pub alg: String,
    pub n: String,
    pub e: String,
}
