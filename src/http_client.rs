use std::time::Duration;

use hyper::{
    client::{Client, HttpConnector},
    Body,
};
use hyper_rustls::HttpsConnector;

pub type HttpClient = Client<HttpsConnector<HttpConnector>, Body>;

/// Create a HTTP client instance.
///
/// Parameter: Timeout for idle sockets being kept-alive
pub fn make_client(pool_idle_timeout_seconds: u64) -> HttpClient {
    let https = HttpsConnector::with_native_roots();
    Client::builder()
        .pool_idle_timeout(Duration::from_secs(pool_idle_timeout_seconds))
        .build(https)
}
