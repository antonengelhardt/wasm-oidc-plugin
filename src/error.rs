// proxy-wasm
use proxy_wasm::traits::HttpContext;

// html
use html_escape::encode_safe;

// thiserror
use thiserror::Error;

// crate
use crate::auth::OidcHttpContext;

/// Error type for the plugin
#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum PluginError {
    // Parsing Errors
    #[error("url is not valid: {0}")]
    UrlError(#[from] url::ParseError),
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
    #[error("the code is coming from an unknown provider: {0}")]
    ProviderNotFoundError(String),
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
    #[error("encryption or decryption failed: {0}")]
    AesError(#[from] aes_gcm::Error),
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

impl OidcHttpContext {
    pub fn show_error_page(&self, status_code: u32, title: &str, message: &str, show_reset_button: bool) {
        let headers = vec![("cache-control", "no-cache"), ("content-type", "text/html")];
        let title = encode_safe(title);
        let message = encode_safe(message);
        let request_id = encode_safe(&self.request_id);
        let reset_button = if show_reset_button {
            r#"<a class="reset-button" href="/_wasm-oidc-plugin/clear-cookies">Reset Cookies</a>"#
        } else {
            ""
        };

        self.send_http_response(
            status_code,
            headers,
            Some(
                format!(
                    r#"
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Error - {status_code}</title>
                        <style>
                            :root {{
                                --bg-color: #f0f2f5;
                                --text-color: #333;
                                --card-bg: #ffffff;
                                --card-border: #e9ecef;
                                --toggle-bg: #e2e8f0;
                                --toggle-border: #cbd5e1;
                                --button-bg: #3498db;
                                --button-text: #ffffff;
                                --button-hover: #2980b9;
                            }}
                            .dark-mode {{
                                --bg-color: #1a1a1a;
                                --text-color: #ffffff;
                                --card-bg: #2c2c2c;
                                --card-border: #4a4a4a;
                                --toggle-bg: #4a5568;
                                --toggle-border: #2d3748;
                                --button-bg: #2980b9;
                                --button-text: #ffffff;
                                --button-hover: #3498db;
                            }}
                            body {{
                                font-family: Helvetica, sans-serif;
                                display: flex;
                                flex-direction: column;
                                justify-content: center;
                                align-items: center;
                                min-height: 100vh;
                                margin: 0;
                                background-color: var(--bg-color);
                                color: var(--text-color);
                                transition: background-color 0.3s ease, color 0.3s ease;
                            }}
                            .error-container {{
                                text-align: center;
                                padding: 40px;
                                background-color: var(--card-bg);
                                border-radius: 12px;
                                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                                max-width: 600px;
                                width: 90%;
                            }}
                            h1 {{
                                margin-bottom: 10px;
                            }}
                            h2 {{
                                margin-bottom: 20px;
                                color: #e74c3c;
                            }}
                            p {{
                                margin-bottom: 10px;
                            }}
                            .request-id {{
                                font-size: 0.8em;
                                color: #888;
                            }}
                            .dark-mode-toggle {{
                                position: fixed;
                                top: 20px;
                                right: 20px;
                            }}
                            .toggle-switch {{
                                position: relative;
                                display: inline-block;
                                width: 60px;
                                height: 34px;
                            }}
                            .toggle-switch input {{
                                opacity: 0;
                                width: 0;
                                height: 0;
                            }}
                            .toggle-slider {{
                                position: absolute;
                                cursor: pointer;
                                top: 0;
                                left: 0;
                                right: 0;
                                bottom: 0;
                                background-color: var(--toggle-bg);
                                border: 2px solid var(--toggle-border);
                                transition: .4s;
                                border-radius: 34px;
                            }}
                            .toggle-slider:before {{
                                position: absolute;
                                content: "☀️";
                                display: flex;
                                align-items: center;
                                justify-content: center;
                                height: 26px;
                                width: 26px;
                                left: 4px;
                                bottom: 2px;
                                background-color: white;
                                transition: .4s;
                                border-radius: 50%;
                            }}
                            input:checked + .toggle-slider {{
                                background-color: var(--toggle-bg);
                            }}
                            input:checked + .toggle-slider:before {{
                                transform: translateX(26px);
                                content: "🌙";
                                background-color: #2c3e50;
                            }}
                            .reset-button {{
                                display: inline-block;
                                margin-top: 20px;
                                padding: 10px 20px;
                                background-color: var(--button-bg);
                                color: var(--button-text);
                                border: none;
                                border-radius: 5px;
                                cursor: pointer;
                                font-size: 16px;
                                text-decoration: none;
                                transition: background-color 0.3s ease;
                            }}
                            .reset-button:hover {{
                                background-color: var(--button-hover);
                            }}
                        </style>
                    </head>
                    <body>
                        <div class="dark-mode-toggle">
                            <label class="toggle-switch">
                                <input type="checkbox" id="darkModeToggle">
                                <span class="toggle-slider"></span>
                            </label>
                        </div>
                        <div class="error-container">
                            <h1>Error {status_code}</h1>
                            <h2>{title}</h2>
                            <p>{message}</p>
                            <p class="request-id">Request-ID: {request_id}</p>
                            {reset_button}
                        </div>
                        <script>
                            const darkModeToggle = document.getElementById('darkModeToggle');
                            const body = document.body;

                            function getDarkModePreference() {{
                                try {{
                                    return localStorage.getItem('darkMode');
                                }} catch (error) {{
                                    console.warn('localStorage is not available', error);
                                    return null;
                                }}
                            }}

                            function setDarkModePreference(value) {{
                                try {{
                                    if (value === null) {{
                                        localStorage.removeItem('darkMode');
                                    }} else {{
                                        localStorage.setItem('darkMode', value);
                                    }}
                                }} catch (error) {{
                                    console.warn('localStorage is not available', error);
                                }}
                            }}

                            darkModeToggle.addEventListener('change', () => {{
                                body.classList.toggle('dark-mode');
                            }});

                            // Check for saved dark mode preference
                            if (getDarkModePreference() === 'enabled') {{
                                body.classList.add('dark-mode');
                                darkModeToggle.checked = true;
                            }}

                            // Save dark mode preference
                            darkModeToggle.addEventListener('change', () => {{
                                if (body.classList.contains('dark-mode')) {{
                                    setDarkModePreference('enabled');
                                }} else {{
                                    setDarkModePreference(null);
                                }}
                            }});
                        </script>
                    </body>
                    </html>
                    "#,
                )
                .as_bytes(),
            ),
        );
    }
}
