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
/// Contains a list of keys that can be used for the validation of the ID Token
pub struct JWKsResponse {
    /// The keys of the jwks response, see `JWK`
    pub keys: Vec<JsonWebKey>,
}

/// [JWK](https://tools.ietf.org/html/rfc7517)
/// Define the structure of each key type that can be used for the validation of the ID Token
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum JsonWebKey {
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
    // Add more key types here
}

/// Struct that defines how the callback looks like to serialize it better
#[derive(Deserialize, Debug)]
pub struct Callback {
    /// The code that is returned from the authorization endpoint
    pub code: String,
}
