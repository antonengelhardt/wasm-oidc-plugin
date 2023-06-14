// serde
use serde::Deserialize;

/// OpenID Connect Discovery
#[derive(Deserialize, Debug)]
pub struct OidcDiscoveryResponse {
    pub issuer: String,
    /// The authorization endpoint to start the code flow
    pub authorization_endpoint: String,
    /// The token endpoint to exchange the code for a token
    pub token_endpoint: String,
    /// The jwks uri to load the jwks response from
    pub jwks_uri: String,
}

#[derive(Deserialize, Debug)]
/// The jwks response (see https://tools.ietf.org/html/rfc7517
pub struct JWKsResponse {
    /// The keys of the jwks response, see `JWK`
    pub keys: Vec<JWK>,
}

#[derive(Deserialize, Debug)]
/// A single key of the jwks response
pub struct JWK {
    /// The key type
    pub kty: String,
    /// The key algorithm
    pub alg: String,
    /// The Public Keys Component n, the modulus
    pub n: String,
    /// The Public Keys Component e, the exponent
    pub e: String,
}
