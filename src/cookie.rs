use serde::{Deserialize, Serialize};
use serde_json;

use log::warn;

/// Struct to hold the state cookie
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
    // Path of the original request
    // pub source: String,
}

impl AuthorizationState {

    /// Create a new cookie from the response coming from the Token Endpoint
    pub fn parse_response(res: &[u8]) -> Result<AuthorizationState, serde_json::Error> {

        // Format the response into a slice and parse it in a struct

        match serde_json::from_slice::<AuthorizationState>(res) {

            // If deserialization was successful, set the cookie and resume the request
            Ok(state) => {
                return Ok(state)
            },
            // If the cookie cannot be parsed into a struct, return an error
            Err(e) => {
                warn!("Error occured during creation of State Cookie {}", e);
                return Err(e)
            }
        }
    }

    /// not used now, but could be used to create a cookie from a response
    pub fn _create_cookie_str(cookie: AuthorizationState) -> String {
        let cookie_str = serde_json::to_string(&cookie).unwrap();
        return cookie_str;
    }

    /// Parse the cookie from the request into a struct
    pub fn parse_cookie(cookie: String) -> Result<AuthorizationState, serde_json::Error> {

        match serde_json::from_str::<AuthorizationState>(&cookie) {

            // If deserialization was successful, set the cookie and resume the request
            Ok(state) => {
                return Ok(state)
                    // source: "/".to_string(),
            },
            // If the cookie cannot be parsed into a struct, return an error
            Err(e) => {
                warn!("Error occured during creation of State Cookie {}", e);
                return Err(e)
            }
        }
    }
}
