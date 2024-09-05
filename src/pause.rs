// log
use log::{info, warn};

// proxy-wasm
use proxy_wasm::{traits::{Context, HttpContext}, types::Action};

/// The PauseRequests Context is the filter struct which is used when the filter is not configured.
/// All requests are paused and queued by the RootContext. Once the filter is configured, the
/// request is resumed by the RootContext.
pub struct PauseRequests {
    /// Original path of the request
    pub original_path: Option<String>,
}

/// The context is used to process incoming HTTP requests when the filter is not configured.
impl HttpContext for PauseRequests {
    /// This function is called when the request headers are received. As the filter is not
    /// configured, the request is paused and queued by the RootContext. Once the filter is
    /// configured, the request is resumed by the RootContext.
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        warn!("plugin not ready, pausing request");

        // Get the original path from the request headers
        self.original_path = Some(
            self.get_http_request_header(":path")
                .unwrap_or("/".to_string()),
        );

        Action::Pause
    }

    /// When the filter is configured, this function is called once the root context resumes the
    /// request. This function sends a redirect to create a new context for the configured filter.
    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        info!("filter now ready, sending redirect");

        // Send a redirect to the original path
        self.send_http_response(
            307,
            vec![
                // Redirect to the requested path
                ("location", self.original_path.as_ref().unwrap()),
                // Disable caching
                ("Cache-Control", "no-cache"),
            ],
            Some(b"Filter is ready now."),
        );
        Action::Continue
    }
}

impl Context for PauseRequests {}
