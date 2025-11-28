/// This module contains all functions, calls and callbacks to execute the OpenID Authorization Code Flow
mod auth;

/// This module contains the structs of the `PluginConfiguration` and `OpenIdConfig`
mod config;

/// This module contains the Open ID discovery and JWKs loading logic
mod discovery;

/// This module contains the error types for the plugin
mod error;

/// This module contains the HTML templates for the auth page and UI elements.
mod html;

/// This module contains the pause context which is used when the filter is not configured.
mod pause;

/// This module contains the responses for the OpenID discovery and jwks endpoints
mod responses;

/// This module contains logic to parse and save the current authorization state in a cookie
mod session;

// std
use std::sync::Mutex;
use std::vec;

// log
use log::info;

// proxy-wasm
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// crate
use crate::discovery::Root;

// This is the initial entry point of the plugin.
proxy_wasm::main! {{

    proxy_wasm::set_log_level(LogLevel::Debug);

    info!("starting plugin");

    // This sets the root context, which is the first context that is called on startup.
    // The root context is used to initialize the plugin and load the configuration from the
    // plugin config and the discovery endpoints.
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(Root {
        plugin_config: None,
        open_id_providers: vec![],
        open_id_resolvers: vec![],
        waiting: Mutex::new(Vec::new()),
        discovery_active: false,
    }) });
}}
