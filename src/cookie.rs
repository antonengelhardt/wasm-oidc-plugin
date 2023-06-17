// serde
use serde::{Deserialize, Serialize};
use serde_json;

// log
use log::warn;

// base64
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64engine, Engine as _};

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

/// Implementation of the AuthorizationState struct
impl AuthorizationState {

    /// Create a new encoded cookie from the response coming from the Token Endpoint
    pub fn create_cookie_from_response(res: &[u8]) -> Result<String, serde_json::Error> {

        // Format the response into a slice and parse it in a struct
        match serde_json::from_slice::<AuthorizationState>(res) {

            // If deserialization was successful, return the cookie
            Ok(state) => {
                // Encode cookie
                let encoded_cookie = base64engine.encode(serde_json::to_string(&state).unwrap().as_bytes());
                Ok(encoded_cookie)
            },
            // If the cookie cannot be parsed into a struct, return an error
            Err(e) => {
                warn!("The response is not in the required format {}", e);
                return Err(e)
            }
        }
    }

    /// Decodee cookie, parse into a struct in order to access the fields and
    /// validate the ID Token
    pub fn parse_and_decode_cookie(cookie: String) -> Result<AuthorizationState, serde_json::Error> {

        // Decode cookie
        let decoded_cookie = base64engine.decode(cookie.as_bytes()).unwrap();

        // Parse cookie into a struct
        match serde_json::from_str::<AuthorizationState>(&String::from_utf8(decoded_cookie).unwrap()) {

            // If deserialization was successful, set the cookie and resume the request
            Ok(state) => {
                return Ok(state)
            },
            // If the cookie cannot be parsed into a struct, return an error
            Err(e) => {
                warn!("The cookie is not matching the required format {}", e);
                return Err(e)
            }
        }
    }
}
