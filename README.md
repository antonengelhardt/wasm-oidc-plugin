## WASM OIDC Plugin

WASM OIDC Envoy Plugin.

It's structure is inherited from [Proxy-Wasm plugin example: HTTP auth
(random)](https://github.com/proxy-wasm/proxy-wasm-rust-sdk/tree/8d1f04aa0de41fc934c2e960ca9bfb091e108bdc/examples/http_auth_random).

### Install Toolchain for WASM in Rust

For developing the [Rust Toolchain](https://www.rust-lang.org/tools/install)
has to be installed and the WASM target has to be enabled.

E.g. for Ubuntu this can be achieved by:

```sh
# Install Build essentials
$ apt install build-essential
# Install Rustup
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Enable WASM compilation target
$ cargo build --target wasm32-wasi --release
```

### Building

```sh
$ cargo build --target wasm32-wasi --release
```

### Testing locally with Envoy

To test [docker](https://www.docker.com/) and [docker
compose](https://docs.docker.com/compose/install/) are needed.

```sh
$ docker compose up
```

Requests to the locally running envoy with the plugin enabled:

```sh
$ curl localhost:10000
```
