// serde
use serde::Deserialize;

/// [OpenID Connect Discovery Response](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig)
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
/// [JWKs response](https://tools.ietf.org/html/rfc7517)
pub struct JWKsResponse {
    /// The keys of the jwks response, see `JWK`
    pub keys: Vec<JWK>,
}

#[derive(Deserialize, Debug)]
pub enum JWK {
    /// A RSA Key of 256 bits
    RS256 {
        /// The key type
        kty: String,
        /// The key algorithm
        alg: String,
        /// The Public Keys Component n, the modulus
        n: String,
        /// The Public Keys Component e, the exponent
        e: String,
    },
}

/// Struct that defines how the callback looks like to serialize it better
#[derive(Deserialize, Debug)]
pub struct Callback {
    /// The code that is returned from the authorization endpoint
    pub code: String,
}
