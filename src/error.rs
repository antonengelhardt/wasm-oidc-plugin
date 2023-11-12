// thiserror
use thiserror::Error;

/// Error type for the plugin
#[derive(Error, Debug)]
pub enum PluginError {
    #[error("error while parsing the configuration file")]
    YamlError(#[from] serde_yaml::Error),
    #[error("error while parsing from json")]
    JsonError(#[from] serde_json::Error),
    #[error("token validation failed")]
    TokenValidationError(#[from] jwt_simple::Error),
    #[error("error while parsing from base64")]
    DecodeError(#[from] base64::DecodeError),
    #[error("decryption failed")]
    DecryptionError(String),
    #[error("no key worked for validation")]
    NoKeyError,
    #[error("error parsing utf8")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("dispatch failed, maybe you forgot to add the upstream?")]
    DispatchError,
    #[error("error while getting code from callback")]
    CodeNotFoundInCallbackError(String),
    #[error("token_id mismatch")]
    TokenIdMismatchError,
    #[error("no body in response")]
    NoBodyError,
    #[error("token response is not in the required format")]
    TokenResponseFormatError(String),
    #[error("token could not be stored in cookie")]
    CookieStoreError(String),
    #[error("cookie could not be validated")]
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
