use std::time::Duration;

use hyper::{
    client::{Client, HttpConnector},
    Body,
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};

pub type HttpClient = Client<HttpsConnector<HttpConnector>, Body>;

/// Create a HTTP 1 client instance.
///
/// Parameter: Timeout for idle sockets being kept-alive
pub fn make_client(pool_idle_timeout_seconds: u64) -> HttpClient {
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder()
        .pool_idle_timeout(Duration::from_secs(pool_idle_timeout_seconds))
        .build(https)
}
