// aes_gcm
use aes_gcm::{aead::AeadMut, Aes256Gcm, Nonce};

// base64
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64engine, Engine as _};

// log
use log::{debug, warn};

// serde
use serde::{Deserialize, Serialize};

// std
use std::fmt::Debug;
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
    /// Create a new session, encrypt it and encode it by using the given cipher and nonce
    /// * `cipher` - Cipher used to encrypt the cookie
    /// * `encoded_nonce` - Nonce used to encrypt the cookie
    pub fn encrypt_and_encode(&self, mut cipher: Aes256Gcm, encoded_nonce: String) -> String {
        // Decode nonce using base64
        let decoded_nonce = base64engine
            .decode(encoded_nonce.as_bytes())
            .expect("nonce didn't match the expected format");

        // Build nonce from decoded nonce
        let nonce = Nonce::from_slice(decoded_nonce.as_slice());

        // Encrypt cookie
        let encrypted_cookie = cipher
            .encrypt(nonce, serde_json::to_vec(&self).unwrap().as_slice())
            .unwrap();

        // Encode cookie and return
        return base64engine.encode(encrypted_cookie.as_slice());
    }

    /// Make the cookie values from the encoded cookie by splitting it into chunks of 4000 bytes and
    /// then building the values to be set in the Set-Cookie headers
    /// * `encoded_cookie` - Encoded cookie to be split into chunks of 4000 bytes
    /// * `cookie_name` - Name of the cookie
    /// * `cookie_duration` - Duration of the cookie in seconds
    /// * `number_current_cookies` - Number of cookies that are currently set (important because otherwise decryption will fail if older and expired cookies are still present)
    pub fn make_cookie_values(
        encoded_cookie: String,
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
                "{}-{}={}; Path=/; HttpOnly; Secure; Max-Age={:?}",
                cookie_name, i, cookie_part, cookie_duration
            );
            cookie_values.push(cookie_value);
        }

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
    ) -> Result<Session, String> {
        // Decode nonce using base64
        // TODO: Idiomatically handle the error
        let decoded_nonce = match base64engine.decode(encoded_nonce.as_bytes()) {
            Ok(nonce) => nonce,
            Err(e) => {
                return Err(format!(
                    "the nonce didn't match the expected format: {}",
                    e.to_string()
                ));
            }
        };

        // Build nonce from decoded nonce
        let nonce = Nonce::from_slice(decoded_nonce.as_slice());

        // Decode cookie using base64
        let decoded_cookie = match base64engine.decode(encoded_cookie.as_bytes()) {
            Ok(cookie) => cookie,
            Err(e) => {
                warn!("the cookie didn't match the expected format: {}", e);
                return Err(e.to_string());
            }
        }; // TODO: Idiomatically handle the error

        // Decrypt cookie
        // TODO: Idiomatically handle the error
        match cipher.decrypt(nonce, decoded_cookie.as_slice()) {
            // If decryption was successful, continue
            Ok(decrypted_cookie) => {
                // Parse cookie into a struct
                match serde_json::from_slice::<Session>(&decrypted_cookie) {
                    // If deserialization was successful, return the session
                    Ok(session) => {
                        debug!("authorization state: {:?}", session);
                        Ok(session)
                    }
                    // If the cookie cannot be parsed into a struct, return an error
                    Err(e) => {
                        warn!("the cookie didn't match the expected format: {}", e);
                        Err(e.to_string())
                    }
                }
            }
            // If decryption failed, return an error
            Err(e) => {
                warn!("decryption failed: {}", e.to_string());
                Err(e.to_string())
            }
        }
    }
}
