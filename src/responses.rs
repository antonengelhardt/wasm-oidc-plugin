// base64
use {
    base64::engine::general_purpose::URL_SAFE_NO_PAD as base64engine_urlsafe, base64::Engine as _,
};

// jwt_simple (upstream / superboring)
use jwt_simple::{
    claims::NoCustomClaims,
    prelude::{RSAPublicKeyLike, VerificationOptions},
    Error,
};

// log
use log::{debug, info};

// serde
use serde::Deserialize;
use url::Url;

/// RSA modulus longer than 4096 bits is 512+ bytes in raw form.
const RSA_MODULUS_BYTES_4096: usize = 512;

/// [OpenID Connect Discovery Response](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig)
#[derive(Deserialize, Debug)]
pub struct OpenIdDiscoveryResponse {
    /// The issuer of the OpenID Connect Provider
    pub issuer: String,
    /// The authorization endpoint to start the code flow
    pub authorization_endpoint: Url,
    /// The token endpoint to exchange the code for a token
    pub token_endpoint: Url,
    /// The URL to logout the user
    pub end_session_endpoint: Option<Url>,
    /// The jwks uri to load the jwks response from
    pub jwks_uri: Url,
}

#[derive(Deserialize, Debug)]
/// [JWKs response](https://tools.ietf.org/html/rfc7517)
/// Contains a list of keys that are retrieved from the jwks uri
pub struct JWKsResponse {
    /// The keys of the jwks response, see `JWK`
    pub keys: Vec<JsonWebKey>,
}

/// [JWK](https://tools.ietf.org/html/rfc7517)
/// Define the structure of each key type that are retrieved from the jwks uri
#[derive(Deserialize, Debug)]
#[serde(tag = "alg")]
pub enum JsonWebKey {
    /// A RSA Key with RS256 algorithm
    RS256 {
        /// The key type like RSA
        kty: String,
        /// The Public Keys Component n, the modulus
        n: String,
        /// The Public Keys Component e, the exponent
        e: String,
    },
    // Add more key types here
}

/// Enum that holds the public keys used to validate ID Tokens.
/// Upstream jwt-simple for normal keys; fork for RSA moduli > 4096 bits.
#[derive(Clone, Debug)]
pub enum SigningKey {
    RS256PublicKey(jwt_simple::algorithms::RS256PublicKey),
    RS256PublicKeyLarge(Box<jwt_simple_fork::algorithms::RS256PublicKey>),
}

impl SigningKey {
    /// Returns `Ok(())` if the token verifies against this key.
    pub fn verify_token(&self, token: &str, options: VerificationOptions) -> Result<(), Error> {
        match self {
            SigningKey::RS256PublicKey(key) => key
                .verify_token::<NoCustomClaims>(token, Some(options))
                .map(|_| ()),
            SigningKey::RS256PublicKeyLarge(key) => {
                use jwt_simple_fork::prelude::RSAPublicKeyLike as _;
                // Cannot use `.into()`: upstream and fork are different crates with the same type names.
                key.verify_token::<jwt_simple_fork::claims::NoCustomClaims>(
                    token,
                    Some(jwt_simple_fork::prelude::VerificationOptions {
                        allowed_issuers: options.allowed_issuers,
                        allowed_audiences: options.allowed_audiences,
                        ..Default::default()
                    }),
                )
                .map(|_| ())
            }
        }
    }
}

impl From<JsonWebKey> for SigningKey {
    fn from(key: JsonWebKey) -> Self {
        match key {
            JsonWebKey::RS256 { kty, n, e, .. } => {
                if kty != "RSA" {
                    debug!("key is not of type RSA although alg is RS256");
                }

                let n_dec = base64engine_urlsafe.decode(n).unwrap();
                let e_dec = base64engine_urlsafe.decode(e).unwrap();

                if n_dec.len() > RSA_MODULUS_BYTES_4096 {
                    info!("RSA modulus >4096 bits; using jwt-simple-fork");
                    SigningKey::RS256PublicKeyLarge(Box::new(
                        jwt_simple_fork::algorithms::RS256PublicKey::from_components(
                            &n_dec, &e_dec,
                        )
                        .expect("failed to parse large RS256 public key"),
                    ))
                } else {
                    info!("loaded RS256 public key");
                    SigningKey::RS256PublicKey(
                        jwt_simple::algorithms::RS256PublicKey::from_components(&n_dec, &e_dec)
                            .expect("failed to parse RS256 public key"),
                    )
                }
            }
        }
    }
}

/// Struct that defines how the callback looks like to serialize it better with serde
#[derive(Deserialize, Debug)]
pub struct CodeCallback {
    /// The code that is returned from the authorization endpoint
    pub code: String,
    /// The state that is returned from the authorization endpoint
    pub state: String,
}

/// Struct that defines how the callback looks like to serialize it better with serde
#[derive(Deserialize, Debug)]
pub struct ProviderSelectionCallback {
    /// The name of the provider that the user selected
    pub authorize_with_provider: String,
    /// The return_to path that the user should be redirected to after the provider selection
    pub return_to: String,
}
