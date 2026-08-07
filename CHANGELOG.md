# Changelog

All notable changes to this project will be documented in this file.

## v0.6.1

### 🚀 Features

- Add /_wasm-oidc-plugin/clear-cookies endpoint and make error page reset button optional

### 🐛 Bug Fixes

- Upgrade actions/deploy-pages from v2 to v4 in documentation workflow
- Improve error handling in authentication process by logging specific cookie validation errors
- Update authority extraction in OpenID response handling
- Remove redundant transport socket configuration in envoy.yaml
- Add SNI configuration for upstream TLS context in configmap.yml
- Enhance path matching and add same-origin check
- Set imagePullPolicy to Always for envoy containers in deployment
- Clarify debug messages regarding session cookie

### 📚 Documentation

- Update README

### 🎨 Styling

- Format error page signature

### ⚙️ Miscellaneous Tasks

- **(ci)** Add separate step to wait for deployment readiness
- Bump upload-pages-artifact from v3 to v4 for Node 24 compatibility
- Stop pushing PR GHCR images during tests
- Update dependencies in Cargo.lock and Cargo.toml to latest versions

### ◀️ Revert

- Restore original PR GHCR workflow

## v0.6.0

### 🚀 Features

- **(discovery)** Multiple oidc providers
- **(discovery)** Configurable `ticking_interval_in_ms` controls ticking
- **(errors)** Use envoy's request-id to log errors and show, helvetica
- **(ci)** Add audit, outdated and verify-project steps
- Add reset button and styling for cookie management
- **(scripts)** Add config migration script for legacy configs

### 🐛 Bug Fixes

- Add footer to auth page and layout fixes
- **(discovery)** Implement Display for ResolverState
- **(logs)** Pretty print discovery reponses debug logs
- **(logs)** Lower case log
- **(html)** Fixed height for all providers cards
- **(discovery)** Fix if host of jwks endpoint is different
- **(exclude)** Get scheme to parse url
- **(logout)** Write something to clear the cookie, refactor cookie fn
- **(ci)** Run test jobs more quickly
- **(html)** Error page has dark mode now!
- Store number of cookie parts in a cookie
- Update cookie attributes to include HttpOnly
- Lints and format
- **(auth)** Replace unwraps with proper error handling
- **(discovery)** Guard config access and retry empty JWKS responses
- **(pause)** Default redirect path when original path is missing
- **(session)** Normalize cookie attribute formatting
- **(html)** Harden localStorage access and improve dark-mode styling
- **(lib)** Set default log level to Info
- **(k8s)** Correct google cluster indentation in example configmap
- Sanitize branch name in Docker tags to handle slashes
- **(ci)** Sanitize PR branch ref before using it as docker tag
- **(scripts)** Emit Rust-compatible claims map and image URL
- **(configmap)** Correct indentation for transport_socket
- **(auth)** Add debug logging for token validation

### 🚜 Refactor

- Split into separate files
- Error page is now generic
- Naming change, more comments and log level changes
- Rebase logout path PR with mulitple providers PR
- `wasm32-wasi` renamed to `wasm32-wasip1` & rust to 1.78
- Rename `ConfiguredOidc` and use inline strings
- Move config parsing to separate function
- **(ci)** Use actions to speed up ci workflows
- **(config)** Update envoy.yaml and migration script
- **(auth)** Update OIDC logout handling and cookie management
- **(config)** Introduce V2PluginConfiguration
- **(config)** Update OIDC configuration and enhance token handling
- **(config)** Allow clippy lint for wrong self convention
- **(deployment)** Update resource requests and limits
- **(tests)** Remove test_migrate_config.py as part of code cleanup
- **(ci)** Remove outdated CI configuration for wasm-oidc-plugin
- **(html)** Implement HTML escaping utility
- **(html)** Replace custom HTML escaping with html_escape crate
- **(logging)** Change log level from Info to Debug
- **(config)** Update OIDC config
- **(config)** Rename cookie_duration in v2 config
- **(auth)** Provider selection logic
- **(config)** Rename cookie_duration to cookie_duration_in_s
- **(rs256)** Use jwt simple crate and fallback to fork for +4096bit
- **(dependencies)** Update jwt-simple fork source, box type and ci
- **(responses)** Change RS256PublicKey to use Box type
- **(dependencies)** Update jwt-simple to legacy version
- **(session)** Remove obsolete comment about current cookies

### 📚 Documentation

- Move social-graphic to .github/assets
- Update readme and examples with multiple providers logic
- Enhance README with state and sequence diagrams for OpenID flow
- Update README to clarify OpenID flow steps and notes
- Update README env vars
- **(readme)** Replace aes_key example with placeholder

### 🎨 Styling

- Fmt
- Clippy lints fixed
- **(fmt)** Order modules
- Fmt
- Use inline variables in html.rs
- Use inline formatting in errors.rs
- Clean up Cargo.toml, chore(deps): upgrade url to 2.5.4
- Rustfmt session.rs after aes-gcm upgrade

### 🧪 Testing

- **(scripts)** Add unit tests for config migration script

### ⚙️ Miscellaneous Tasks

- Pr template
- Add audit.toml file
- Remove dead code
- Update cargo-deny action to v2
- Update build target from wasm32-wasi to wasm32-wasip1
- Update Docker image references and fix ci
- Update CHANGELOG formatting for consistency and clarity
- Upgrade Envoy image to v1.36
- Update CI configuration for wasm32-wasip1 target and optimise ci
- Refactor CI workflow to use actions instead of image
- Add rust-toolchain and use fixed rust version
- Update CI and deployment configurations for wasm32-wasip1 target
- **(demo)** Redact client credentials in example configmap
- Verify pinned rust toolchain in test workflow
- **(ci)** Upgrade rust toolchain to 1.97.1
- **(docker)** Upgrade envoy image to v1.39-latest
- **(deny)** Allow BSD-2-Clause and Zlib transitive licenses

## v0.5.4

### 🎨 Styling

- Clean up Cargo.toml, chore(deps): upgrade url to 2.5.4

### ⚙️ Miscellaneous Tasks

- **(deny)** Upgrade cargo-deny to v2 action
- **(deny)** New template
- **(ci)** Add audit, outdated and verify-project checks
- **(audit)** Add audit.toml file & downgrade lockfile to v3

## v0.5.3

### 🚜 Refactor

- `wasm32-wasi` renamed to `wasm32-wasip1` & rust to 1.78

## v0.5.2

### 🐛 Bug Fixes

- **(dependabot)** Remove unnecessary scope and "update" prefix
- **(dependabot)** Extra space

### ⚙️ Miscellaneous Tasks

- **(git)** Add git hooks
- Pr template
- **(ci)** Disable automatic changelog and release
- **(ci)** Bump upload-artifact from v2 to v4
- **(ci)** Bump upload-artifact from v2 to v4 in build.yaml

## v0.5.1

### ⚙️ Miscellaneous Tasks

- **(deps)**: update proxy-wasm to v0.2.2 (from v0.2.1)

## v0.5.0

### 🐛 Bug Fixes

- **(ci)** Brackets missed, changelog fixed

## v0.4.13

### 🐛 Bug Fixes

- **(ci)** Sed v0.5.0 in Changelog

## v0.4.12

### 🐛 Bug Fixes

- **(ci)** Move release and changelog to on push workflow and skip if commit is release commit

## v0.4.11

### 🐛 Bug Fixes

- **(ci)** Use gh env to skip steps

## v0.4.9

### 🐛 Bug Fixes

- **(ci)** Commit message fixed and header stripped from changelog
- **(ci)** Only trigger release if commit is not release commit
- **(ci)** Cant type, changelog cleaned

### ⚙️ Miscellaneous Tasks

- **(release)** Prepare for v0.4.8
- **(release)** Prepare for v0.4.9

## v0.4.8

### 🐛 Bug Fixes

- **(ci)** Use deploy key because one action cant trigger the next :(
- **(ci)** Release workflow uses normal bot user to not cause a loop
- **(ci)** Release workflow should not remove old and add new tag

### ⚙️ Miscellaneous Tasks

- **(release)** Prepare for v0.4.8

## v0.4.6

- Bump serde from 1.0.200 to 1.0.201
- Bump serde_json from 1.0.116 to 1.0.117
- Bump thiserror from 1.0.59 to 1.0.60

## v0.4.5

- Bug: parse `issuer` as `String` and not as `Url` as it caused issuer mismatches during token validation

## v0.4.4

- Bug: If auth state is missing in the session and token validation is off, use match to safely unwrap

## v0.4.3

- Prevent AES nonce reuse
- Idiomatic error handling
- k8s: httpbin pod as demo project target

## v0.4.2

- Bump serde from 1.0.197 to 1.0.198
- Bump serde_json from 1.0.115 to 1.0.116
- ci: separate jobs and caching
- Healthchecks for Kubernetes

## v0.4.1

- Demo project: deployment files and readme
- Bump serde_yaml from 0.9.32 to 0.9.33
- Bump regex from 1.10.3 to 1.10.4
- Bump serde_json from 1.0.114 to 1.0.115

## v0.4.0

- State verification to prevent CSRF attacks
- Rewrite cookie logic to get rid of `code-verifier` and `original-path` cookies
- Config value checks
- VSCode Settings to Format on Save
- Add fmt and Clippy to CI

## v0.3.4

- Check for three Host Headers
- Default URL Headers
- Envoy Docker Image to 1.29
- Missing config in Configmap added
- OIDC Plugin Name added
- Fix Pre Built Deployment File Mounting
- GHCR Image Push

## v0.3.3

- Fix Docker-Build Version

## v0.3.2

- Add Kubernetes examples
- Explain why to use this repo

## v0.3.1

- Filter Proxy Cookies and do not forward them to the backend

## v0.3.0

- Add support for forwarding the access token to the backend

## v0.2.0

- Make Token Validation optional and configurable
- Support for other key types added
- Replace JWT Simple crate with modified one

## v0.1.4

- Replace Rust Docker Image with own one

## v0.1.1

- Workflows for Build & Docs

## v0.1.0

- Redirect to Authorization Endpoint
- Exchange Code for Token
- Validate Token
- Encrypt and Decrypt Cookies
- Load Configuration from Endpoint
- Configuration options
- Exclude Hosts, Paths, URLs
- Reload Interval
- Docker-Compose Example
