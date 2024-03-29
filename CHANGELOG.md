# Changelog

## 0.4.0

* State verification to prevent CSRF attacks
* Rewrite cookie logic to get rid of `code-verifier` and `original-path` cookies
* Config value checks
* VSCode Settings to Format on Save
* Add fmt and Clippy to CI

## 0.3.4

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
