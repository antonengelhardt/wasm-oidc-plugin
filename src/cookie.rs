// aes_gcm
use aes_gcm::{
    aead::{AeadMut, OsRng},
    AeadCore, Aes256Gcm,
};

// base64
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64engine, Engine as _};

// log
use log::debug;

// std
use std::fmt::Debug;

// serde
use serde::{Deserialize, Serialize};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// ID token in JWT format
    pub id_token: String,
}

/// Struct that holds all information about the current session including the authorization state,
/// the original path, the PKCE code verifier and the state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Authorization state
    pub authorization_state: Option<AuthorizationState>,
    /// Original Path to which the user should be redirected after login
    pub original_path: String,
    /// PKCE Code Verifier used to generate the PKCE Code Challenge
    pub code_verifier: String,
    /// State used to prevent CSRF attacks
    pub state: String,
}

impl Session {
    /// Create a new session, encrypt it and encode it by using the given cipher
    /// * `cipher` - Cipher used to encrypt the cookie
    ///
    /// Returns:
    /// * the base64 encoded encrypted session data
    /// * the base64 encoded nonce needed to decrypt it
    pub fn encrypt_and_encode(
        &self,
        mut cipher: Aes256Gcm,
    ) -> Result<(String, String), PluginError> {
        // Generate nonce and encode it
        // We generate the nonce here to make sure we never encrypt with the same nonce twice
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let encoded_nonce = base64engine.encode(nonce.as_slice());

        // Encrypt and encode cookie
        let encrypted_cookie = cipher.encrypt(&nonce, serde_json::to_vec(&self)?.as_slice())?;
        let encoded_cookie = base64engine.encode(encrypted_cookie.as_slice());

        debug!("encrypted with nonce: {}", &encoded_nonce);

        Ok((encoded_cookie, encoded_nonce))
    }

    /// Make the cookie values from the encoded cookie by splitting it into chunks of 4000 bytes and
    /// then building the values to be set in the Set-Cookie headers
    /// * `encoded_cookie` - Encoded cookie to be split into chunks of 4000 bytes
    /// * `encoded_nonce` - Base64 encoded nonce needed to decrypt the cookie
    /// * `cookie_name` - Name of the cookie
    /// * `cookie_duration` - Duration of the cookie in seconds
    /// * `number_current_cookies` - Number of cookies that are currently set (important because otherwise decryption will fail if older and expired cookies are still present)
    pub fn make_cookie_values(
        encoded_cookie: &str,
        encoded_nonce: &str,
        cookie_name: &str,
        cookie_duration: u64,
        number_current_cookies: u64,
    ) -> Vec<String> {
        // Split every 4000 bytes
        let cookie_parts = encoded_cookie
            .as_bytes()
            .chunks(4000)
            .map(|chunk| std::str::from_utf8(chunk)
            .expect("auth_cookie is base64 encoded, which means ASCII, which means one character = one byte, so this is valid"));

        let mut cookie_values = vec![];

        // Build the cookie values
        for (i, cookie_part) in cookie_parts.enumerate() {
            let cookie_value = format!(
                "{}-{}={}; Path=/; HttpOnly; Secure; Max-Age={}",
                cookie_name, i, cookie_part, cookie_duration
            );
            cookie_values.push(cookie_value);
        }

        // Build nonce cookie value
        let nonce_cookie_value = format!(
            "{}-nonce={}; Path=/; HttpOnly; Secure; Max-Age={}; ",
            cookie_name, &encoded_nonce, cookie_duration
        );
        cookie_values.push(nonce_cookie_value);

        // Overwrite the old cookies because decryption will fail if older and expired cookies are
        // still present.
        for i in cookie_values.len()..number_current_cookies as usize {
            cookie_values.push(format!(
                "{}-{}=; Path=/; HttpOnly; Secure; Max-Age=0",
                cookie_name, i
            ));
        }

        cookie_values
    }

    /// Make the Set-Cookie headers from the cookie values
    /// * `cookie_values` - Cookie values to be set in the Set-Cookie headers
    pub fn make_set_cookie_headers(cookie_values: &[String]) -> Vec<(&'static str, &str)> {
        // Build the cookie headers
        let set_cookie_headers: Vec<(&str, &str)> = cookie_values
            .iter()
            .map(|v| ("Set-Cookie", v.as_str()))
            .collect();

        // Return the cookie headers
        set_cookie_headers
    }

    /// Decode cookie, parse into a struct in order to access the fields
    /// * `encoded_cookie` - Encoded cookie to be decoded and parsed into a struct
    /// * `cipher` - Cipher used to decrypt the cookie
    /// * `encoded_nonce` - Nonce used to decrypt the cookie
    pub fn decode_and_decrypt(
        encoded_cookie: String,
        mut cipher: Aes256Gcm,
        encoded_nonce: String,
    ) -> Result<Session, PluginError> {
        // Decode nonce using base64
        debug!("decrypting with nonce: {}", encoded_nonce);
        let decoded_nonce = base64engine.decode(encoded_nonce.as_bytes())?;
        let nonce = aes_gcm::Nonce::from_slice(decoded_nonce.as_slice());

        // Decode cookie using base64
        let decoded_cookie = base64engine.decode(encoded_cookie.as_bytes())?;

        // Decrypt with cipher
        let decrypted_cookie = cipher.decrypt(nonce, decoded_cookie.as_slice())?;

        // Parse cookie into a struct
        let state = serde_json::from_slice::<Session>(&decrypted_cookie)?;
        debug!("state: {:?}", state);
        Ok(state)
    }
}
