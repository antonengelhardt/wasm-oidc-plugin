# WASM OIDC Plugin

A plugin for [Envoy](https://www.envoyproxy.io/) written in [Rust](https://www.rust-lang.org).

It is a HTTP Filter, that implements the OIDC Authorization Code Flow. Requests sent to the filter are checked for the presence of a valid session cookie. If the cookie is not present, the user is redirected to the OIDC provider to authenticate. After successful authentication, the user is redirected back to the original request.

## Install

### Install Toolchain for WASM in Rust

For developing the [Rust Toolchain](https://www.rust-lang.org/tools/install)
has to be installed and the WASM target has to be enabled.

E.g. for Ubuntu this can be achieved by:

```sh
# Install Build essentials
apt install build-essential
# Install Rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Enable WASM compilation target
cargo build --target wasm32-wasi --release
```

## Try it out

Shortcut:

```sh
make simulate
```

### The long version

Building the plugin:

```sh
cargo build --target wasm32-wasi --release
```

Testing locally with Envoy:

To test [docker](https://www.docker.com/) and [docker-compose](https://docs.docker.com/compose/install/) are needed.

```sh
docker compose up
```

Requests to the locally running envoy with the plugin enabled:

```sh
curl localhost:10000
```

## Documentation

To generate a detailed documentation, run:

```sh
cargo doc --document-private-items --open
```


### Configuration

The plugin is configured via the `envoy.yaml` file. The following configuration options are required:

| Name | Type | Description | Example |
| ---- | ---- | ----------- | ------- |
| `config_endpoint` | `string` | The OIDC configuration endpoint. | `https://accounts.google.com/.well-known/openid-configuration` |
| `reload_interval_in_hours` | `u64` | The interval in hours, after which the OIDC configuration is reloaded. | `24` |
| `exclude_hosts` | `Vec<String>` | A comma separated list Hosts (in Regex expressions), that are excluded from the OIDC authentication. | [`localhost:10000`] |
| `exclude_paths` | `Vec<String>` | A comma separated list of paths (in Regex expressions), that are excluded from the OIDC authentication. | [`/health`] |
| `exclude_urls` | `Vec<String>` | A comma separated list of URLs, that are excluded from the OIDC authentication. | [`localhost:10000/health`] |
| `cookie_name` | `string` | The name of the cookie, that is used to store the session. | `oidcSession` |
| `cookie_duration` | `u64` | The duration in seconds, after which the session cookie expires. | `86400` |
| `authority` | `string` | The authority of the OIDC provider. | `accounts.google.com` |
| `redirect_uri` | `string` | The redirect URI, that is used to redirect the user back to the original request. | `http://localhost:10000/oidc/callback` |
| `client_id` | `string` | The client ID, that consumes the OIDC plugin. | `wasm-oidc-plugin` |
| `scope` | `string` | The scope, to validate | `openid email` |
| `claims` | `string` | The claims, to validate | `{\"id_token\":{\"email\":null}}` |
| `client_secret` | `string` | The client secret, that is used to authenticate with the OIDC provider. | `secret` |
| `audience` | `string` | The audience, that is used to validate the token. | `wasm-oidc-plugin` |

With these configuration options, the plugin starts and loads more information itself such as the OIDC provider's public keys, issuer, etc.

For that a state is used, which determines, what to load next. The following state are possbile and depending on the outcome, the state is changed or not:

| State | Description |
| ---- | ----------- |
| `Uninitialized` | The plugin is not initialized yet. |
| `LoadingConfig` | The plugin is loading the OIDC configuration from the `config_endpoint`. |
| `LoadingJwks` | The plugin is loading the OIDC provider's public keys from the `jwks_uri`. |
| `Ready` | The plugin is ready to handle request and will reload the OIDC configuration after the `reload_interval_in_hours` has passed. |

### Handling a request

When a new request arrives, the root context creates a new http context with the information that has been loaded previously.

Then, one of the following cases is handled:

1. The filter is not configured yet and still loading the OIDC configuration. The request paused and queued until the configuration is loaded. Then, the RootContext resumes the request and the Request is redirecting in order to create a new context.
2. The request has the code parameter in the URL query. This means that the user has been redirected back from the OIDC provider after successful authentication. The plugin exchanges the code for a token using the `token_endpoint` and stores the token in the session. Then, the user is redirected back to the original request.
3. The request has a valid session cookie. The plugin validates the token in the session and passes the request.
4. The request has no valid session cookie. The plugin redirects the user to the OIDC provider to authenticate. Once, the user returns, the first case is handled.

## Tools

### Gitleaks

We are using [Gitleaks](https://github.com/gitleaks/gitleaks) to protect from unwanted secret leaking and prevent security incidents by detecting passwords, secrets, API keys, tokens and more in git repos.

To run gitleaks, install it first and then run:

```bash
gitleaks protect

# To get the list of leaks
gitleaks protect --verbose
```

If you want to install a pre-commit hook - you should - install [pre-commit](https://pre-commit.com/) and run (from the root of the project):

```bash
pre-commit install
```
