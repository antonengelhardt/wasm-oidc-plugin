/// Generate provider card HTML
///
/// ## Arguments
///
/// * `url` - URL to redirect to
/// * `name` - Name of the provider
/// * `logo` - URL to the logo of the provider
pub fn provider_card(url: &str, name: &str, logo: &str) -> String {
    format!(
        r#"
                <a href="{}" class="provider-link">
                    <div class="provider-card">
                        <div class="logo-container">
                            <img src="{}" alt="{}" class="provider-logo">
                        </div>
                        <h2 class="provider-name">{}</h2>
                    </div>
                </a>
            "#,
        url, logo, name, name
    )
}

/// Generate the HTML for the authentication page
///
/// ## Arguments
///
/// * `provider_cards` - HTML of the provider cards
pub fn auth_page_html(provider_cards: String) -> String {
    let version = env!("CARGO_PKG_VERSION");
    format!(
        r#"
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Select Authentication Provider</title>
                <style>
                    :root {{
                        --bg-color: #f0f2f5;
                        --text-color: #333;
                        --card-bg: #ffffff;
                        --card-text: #333;
                        --card-footer-bg: #f8f9fa;
                        --card-border: #e9ecef;
                        --toggle-bg: #e2e8f0;
                        --toggle-border: #cbd5e1;
                        --hover-border: #3498db;
                        --footer-text: #888;
                    }}
                    .dark-mode {{
                        --bg-color: #1a1a1a;
                        --text-color: #ffffff;
                        --card-bg: #2c2c2c;
                        --card-text: #ffffff;
                        --card-footer-bg: #383838;
                        --card-border: #4a4a4a;
                        --toggle-bg: #4a5568;
                        --toggle-border: #2d3748;
                        --hover-border: #3498db;
                        --footer-text: #888;
                    }}
                    body {{
                        font-family: Arial, sans-serif;
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
                    .container {{
                        text-align: center;
                        padding: 20px;
                        max-width: 800px;
                        width: 100%;
                    }}
                    h1 {{
                        margin-bottom: 30px;
                    }}
                    .provider-grid {{
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 20px;
                        justify-content: center;
                        padding: 20px;
                    }}
                    .provider-card {{
                        background-color: var(--card-bg);
                        border-radius: 12px;
                        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                        transition: all 0.3s ease;
                        overflow: hidden;
                        position: relative;
                        display: flex;
                        flex-direction: column;
                        height: 200px;
                    }}
                    .provider-card::before {{
                        content: '';
                        position: absolute;
                        top: 0;
                        left: 0;
                        right: 0;
                        bottom: 0;
                        border-radius: 12px;
                        border: 2px solid transparent;
                        transition: border-color 0.3s ease;
                    }}
                    .provider-link:hover .provider-card {{
                        transform: translateY(-5px);
                        box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15);
                    }}
                    .provider-link:hover .provider-card::before {{
                        border-color: var(--hover-border);
                    }}
                    .provider-link {{
                        display: block;
                        text-decoration: none;
                        color: var(--card-text);
                    }}
                    .logo-container {{
                        flex-grow: 1;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        padding: 30px;
                        background-color: var(--card-bg);
                        height: 140px;
                    }}
                    .provider-logo {{
                        max-width: 80%;
                        max-height: 80px;
                        width: auto;
                        height: auto;
                        object-fit: contain;
                        mix-blend-mode: darken;
                    }}
                    .dark-mode .provider-logo {{
                        mix-blend-mode: lighten;
                    }}
                    .provider-name {{
                        font-size: 18px;
                        margin: 0;
                        padding: 15px;
                        background-color: var(--card-footer-bg);
                        border-top: 1px solid var(--card-border);
                        flex-shrink: 0;
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
                    .footer {{
                        position: fixed;
                        bottom: 20px;
                        margin-top: 20px;
                        color: var(--footer-text);
                        font-size: 14px;
                    }}
                    .footer a {{
                        color: var(--footer-text);
                        text-decoration: none;
                    }}
                    .footer a:hover {{
                        text-decoration: underline;
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
                <div class="container">
                    <h1>Select a provider to authenticate with</h1>
                    <div class="provider-grid">
                        {}
                    </div>
                </div>
                <div class="footer">
                    <a href="https://github.com/antonengelhardt/wasm-oidc-plugin" target="_blank" rel="noopener noreferrer">wasm-oidc-plugin</a> v{}
                </div>
                <script>
                    const darkModeToggle = document.getElementById('darkModeToggle');
                    const body = document.body;

                    function updateLogoVisibility() {{
                        const logos = document.querySelectorAll('.provider-logo');
                        logos.forEach(logo => {{
                            logo.style.visibility = 'hidden';
                            setTimeout(() => {{
                                logo.style.visibility = 'visible';
                            }}, 0);
                        }});
                    }}

                    darkModeToggle.addEventListener('change', () => {{
                        body.classList.toggle('dark-mode');
                        updateLogoVisibility();
                    }});

                    // Check for saved dark mode preference
                    if (localStorage.getItem('darkMode') === 'enabled') {{
                        body.classList.add('dark-mode');
                        darkModeToggle.checked = true;
                    }}

                    // Save dark mode preference
                    darkModeToggle.addEventListener('change', () => {{
                        if (body.classList.contains('dark-mode')) {{
                            localStorage.setItem('darkMode', 'enabled');
                        }} else {{
                            localStorage.setItem('darkMode', null);
                        }}
                    }});

                    // Call updateLogoVisibility on page load
                    updateLogoVisibility();
                </script>
            </body>
            </html>
            "#,
        provider_cards, version
    )
}
