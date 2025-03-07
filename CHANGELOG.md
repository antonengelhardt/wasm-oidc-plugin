# Changelog

All notable changes to this project will be documented in this file.

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

- *(ci)* Move release and changelog to on push workflow and skip if commit is release commit

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

* Bump serde from 1.0.200 to 1.0.201
* Bump serde_json from 1.0.116 to 1.0.117
* Bump thiserror from 1.0.59 to 1.0.60

## v0.4.5

* Bug: parse `issuer` as `String` and not as `Url` as it caused issuer mismatches during token validation

## v0.4.4

* Bug: If auth state is missing in the session and token validation is off, use match to safely unwrap

## v0.4.3

* Prevent AES nonce reuse
* Idiomatic error handling
* k8s: httpbin pod as demo project target

## v0.4.2

* Bump serde from 1.0.197 to 1.0.198
* Bump serde_json from 1.0.115 to 1.0.116
* ci: separate jobs and caching
* Healthchecks for Kubernetes

## v0.4.1

* Demo project: deployment files and readme
* Bump serde_yaml from 0.9.32 to 0.9.33
* Bump regex from 1.10.3 to 1.10.4
* Bump serde_json from 1.0.114 to 1.0.115

## v0.4.0

* State verification to prevent CSRF attacks
* Rewrite cookie logic to get rid of `code-verifier` and `original-path` cookies
* Config value checks
* VSCode Settings to Format on Save
* Add fmt and Clippy to CI

## v0.3.4

* Check for three Host Headers
* Default URL Headers
* Envoy Docker Image to 1.29
* Missing config in Configmap added
* OIDC Plugin Name added
* Fix Pre Built Deployment File Mounting
* GHCR Image Push

## v0.3.3

* Fix Docker-Build Version

## v0.3.2

* Add Kubernetes examples
* Explain why to use this repo

## v0.3.1

* Filter Proxy Cookies and do not forward them to the backend

## v0.3.0

* Add support for forwarding the access token to the backend

## v0.2.0

* Make Token Validation optional and configurable
* Support for other key types added
* Replace JWT Simple crate with modified one

## v0.1.4

* Replace Rust Docker Image with own one

## v0.1.1

* Workflows for Build & Docs

## v0.1.0

* Redirect to Authorization Endpoint
* Exchange Code for Token
* Validate Token
* Encrypt and Decrypt Cookies
* Load Configuration from Endpoint
* Configuration options
* Exclude Hosts, Paths, URLs
* Reload Interval
* Docker-Compose Example
