// std
use std::sync::Mutex;
use std::vec;


// log
use log::info;

// proxy-wasm
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// url

/// This module contains logic to parse and save the current authorization state in a cookie
mod session;

/// This module contains the structs of the `PluginConfiguration` and `OpenIdConfig`
mod config;

/// This module contains the OIDC discovery and JWKs loading logic
mod discovery;

/// This module contains the responses for the OIDC discovery and jwks endpoints
mod responses;

/// This module contains the error types for the plugin
mod error;

/// This module contains the HTML templates for the auth page and UI elements.
mod html;

/// This module contains the pause context which is used when the filter is not configured.
mod pause;

mod auth;

// crate
use crate::discovery::Root;

// This is the initial entry point of the plugin.
proxy_wasm::main! {{

    proxy_wasm::set_log_level(LogLevel::Debug);

    info!("Starting plugin");

    // This sets the root context, which is the first context that is called on startup.
    // The root context is used to initialize the plugin and load the configuration from the
    // plugin config and the discovery endpoints.
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(Root {
        plugin_config: None,
        open_id_providers: Mutex::new(vec![]),
        open_id_resolvers: Mutex::new(vec![]),
        waiting: Mutex::new(Vec::new()),
        discovery_active: false,
    }) });
}}
