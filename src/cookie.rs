// aes_gcm
use aes_gcm::{Aes256Gcm, aead::{OsRng, AeadMut}, AeadCore};

// base64
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64engine, Engine as _};

// log
use log::debug;
use std::fmt::Debug;

// serde
use serde::{Deserialize, Serialize};
use serde_json;

use crate::error::PluginError;

/// Struct parse the cookie from the request into a struct in order to access the fields and
/// also to save the cookie on the client side
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationState {
    /// Access token to be used for requests to the API
    pub access_token: String,
    /// Type of the access token
    pub token_type: String,
    /// Time in seconds until the access token expires
    pub expires_in: u32,
    /// Refresh token to be used to refresh the access token
    pub refresh_token: String,
    /// ID token in JWT format
    pub id_token: String,
}

/// Struct that holds the encoded cookie and the encoded nonce as well as the access token and the id token
pub struct EncodedCookies {
    /// Encoded cookie
    pub encoded_cookie: String,
    /// Encoded nonce
    pub encoded_nonce: String,
    /// Access token
    pub access_token: String,
    /// ID token
    pub id_token: String,
}

/// Implementation of the AuthorizationState struct
impl AuthorizationState {

    /// Create a new encoded cookie from the response coming from the Token Endpoint
    pub fn create_cookie_from_response(mut cipher: Aes256Gcm, res: &[u8]) -> Result<EncodedCookies, String> {

        // Format the response into a slice and parse it in a struct
        let state = serde_json::from_slice::<AuthorizationState>(&res)?;

        // Generate nonce and encode it
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let encoded_nonce = base64engine.encode(nonce.as_slice());

        // Encrypt cookie
        let encrypted_cookie = cipher.encrypt(&nonce, serde_json::to_vec(&state).unwrap().as_slice())
            .map_err(|e| PluginError::DecryptionError(e))?;

        // Encode cookie
        let encoded_cookie = base64engine.encode(encrypted_cookie.as_slice());

        Ok(EncodedCookies {
            encoded_cookie,
            encoded_nonce,
            access_token: state.access_token,
            id_token: state.id_token,
        })
    }

    /// Decode cookie, parse into a struct in order to access the fields and
    /// validate the ID Token
    pub fn decode_and_decrypt_cookie(cookie: String, mut cipher: Aes256Gcm, nonce: String) -> Result<AuthorizationState, PluginError> {

        // Decode nonce using base64
        let decoded_nonce = base64engine.decode(nonce.as_bytes())?;
        let nonce = aes_gcm::Nonce::from_slice(decoded_nonce.as_slice());
        debug!("Nonce: {:?}", nonce);

        // Decode cookie using base64
        let decoded_cookie = base64engine.decode(cookie.as_bytes())?;

        // Decrypt with cipher
        let decrypted_cookie = cipher.decrypt(nonce, decoded_cookie.as_slice())
            .map_err(|e| PluginError::DecryptionError(e))?;

        // Parse into struct and return
        Ok(serde_json::from_slice::<AuthorizationState>(&decrypted_cookie)?)
    }
}
