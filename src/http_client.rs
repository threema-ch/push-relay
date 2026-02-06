use std::time::Duration;

use reqwest::{Client, Error};

/// Create a HTTP 1 client instance.
///
/// Parameter: Timeout for idle sockets being kept-alive
pub fn make_client(pool_idle_timeout_seconds: u64) -> Result<Client, Error> {
    Client::builder()
        .pool_idle_timeout(Duration::from_secs(pool_idle_timeout_seconds))
        .http1_only()
        .use_rustls_tls()
        .https_only(!cfg!(test))
        .build()
}
