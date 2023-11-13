// thiserror
use thiserror::Error;

/// Error type for the plugin
#[derive(Error, Debug)]
pub enum PluginError {
    // Parsing Errors
    #[error("error while parsing the configuration file: {0}")]
    YamlError(#[from] serde_yaml::Error),
    #[error("error while parsing from json: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("error parsing utf8: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("error while parsing from base64: {0}")]
    DecodeError(#[from] base64::DecodeError),

    // Token validation errors
    #[error("error while getting code from callback: {0}")]
    CodeNotFoundInCallbackError(#[from] serde_urlencoded::de::Error),
    #[error("token response is not in the required format: {0}")]
    TokenResponseFormatError(String),
    #[error("token validation failed: {0}")]
    TokenValidationError(#[from] jwt_simple::Error),
    #[error("no key worked for validation")]
    NoKeyError,

    // HTTP errors
    #[error("dispatch failed, maybe you forgot to add the upstream?")]
    DispatchError,
    #[error("token_id mismatch")]
    TokenIdMismatchError,
    #[error("no body in response")]
    NoBodyError,

    // Cookie errors
    #[error("decryption failed: {0}")]
    DecryptionError(aes_gcm::aead::Error),
    #[error("token could not be stored in cookie: {0}")]
    CookieStoreError(String),
    #[error("cookie is not valid: {0}")]
    CookieValidationError(String),
    #[error("session cookie not found")]
    SessionCookieNotFoundError,
    #[error("nonce cookie not found")]
    NonceCookieNotFoundError,
    #[error("authorization state not found")]
    AuthorizationStateNotFoundError,
    #[error("state does not match")]
    StateMismatchError,
}
