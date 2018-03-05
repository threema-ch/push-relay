use std::str::{FromStr, from_utf8};

use futures::Stream;
use futures::future::{self, Future};
use hyper::{Client, StatusCode, Request, Method, Uri, Chunk};
use hyper::header::{ContentType, Authorization};
use hyper_tls::HttpsConnector;
use rustc_serialize::json;
use tokio_core::reactor::Handle;
use chrono::Utc;

use ::errors::PushError;
use ::utils::BoxedFuture;

#[cfg(test)]
use mockito::SERVER_URL;

#[cfg(not(test))]
static GCM_ENDPOINT: &'static str = "https://android.googleapis.com";

#[cfg(test)]
static GCM_ENDPOINT: &'static str = SERVER_URL;
static GCM_PATH: &'static str = "/gcm/send";

#[derive(Debug, RustcEncodable)]
struct Data<'a> {
    /// Session id (public key of the initiator)
    wcs: &'a str,
    /// Timestamp
    wct: i64,
    /// Version
    wcv: u16,
}

#[derive(Debug, RustcEncodable)]
#[allow(non_camel_case_types, dead_code)]
pub enum Priority {
    high,
    normal,
}

#[derive(Debug, RustcEncodable)]
struct Payload<'a> {
    to: &'a str,
    priority: Priority,
    time_to_live: u32,
    data: Data<'a>,
}

#[derive(Debug, RustcDecodable)]
pub struct MessageResult {
    pub message_id: String,
    pub registration_id: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, RustcDecodable)]
pub struct MessageResponse {
    pub multicast_id: i64,
    pub success: i64,
    pub failure: i64,
    pub canonical_ids: i64,
    pub results: Option<Vec<MessageResult>>,
}

/// Return the current unix epoch timestamp
fn get_timestamp() -> i64 {
    Utc::now().timestamp()
}

/// Send a push notification.
///
/// TODO: Once the next release is out, remove Option around version.
pub fn send_push(
    handle: Handle,
    api_key: String,
    push_token: &str,
    version: u16,
    session: &str,
    priority: Priority,
    ttl: u32,
) -> BoxedFuture<MessageResponse, PushError> {
    let data = Data { wcs: session, wct: get_timestamp(), wcv: version };
    let payload = Payload { to: push_token, priority: priority, time_to_live: ttl, data: data };

    // Create async HTTP client instance
    let https_connector = match HttpsConnector::new(4, &handle) {
        Ok(conn) => conn,
        Err(e) => return boxed!(future::err(
            PushError::Other(format!("Could not create HttpsConnector: {}", e))
        ))
    };
    let client = Client::configure()
        .connector(https_connector)
        .build(&handle);

    // Encode payload
    let payload_string = json::encode(&payload).expect("Could not encode JSON payload");
    debug!("Payload: {}", payload_string);

    // Build response future
    let response_future = client.request({
        let uri = Uri::from_str(&(GCM_ENDPOINT.to_string() + GCM_PATH)).unwrap();
        let mut req = Request::new(Method::Post, uri);
        req.headers_mut().set(Authorization(format!("key={}", api_key)));
        req.headers_mut().set(ContentType::json());
        req
    }).map_err(|e| PushError::Other(format!("GCM request failed: {}", e)));

    let body_read_error = |e| PushError::Other(format!("Could not read GCM response body: {}", e));

    // Process response
    let chunk_future = response_future.and_then(|response| { // Future<Item=Chunk, Error=PushError>
        match response.status() {
            StatusCode::Ok =>
                boxed!(response.body().concat2().map_err(body_read_error)),
            StatusCode::BadRequest =>
                boxed!(future::err(PushError::ProcessingError("400 Bad Request".into()))),
            StatusCode::Unauthorized =>
                boxed!(future::err(PushError::ProcessingError("Unauthorized. Is the API token correct?".into()))),
            _ =>
                boxed!(response.body().concat2()
                    .map_err(body_read_error)
                    .and_then(|chunk| {
                        match from_utf8(&*chunk) {
                            Ok(body) => Err(PushError::Other(format!("Unknown error: {}", body))),
                            Err(_) => Err(PushError::Other("Unknown error (and non-UTF-8 body)".into())),
                        }
                    })
                )
        }
    });

    // Process response body
    boxed!(chunk_future.and_then(|chunk: Chunk| {
        // Decode UTF8 bytes
        let json_body = from_utf8(&*chunk)
            .map_err(|_| PushError::Other("Could not decode response JSON: Invalid UTF-8".into()))?;

        // Parse JSON
        let data = json::decode::<MessageResponse>(json_body)
            .map_err(|e| PushError::Other(
                format!("Could not decode response JSON: `{}` (Reason: {})", json_body, e)
            ))?;

        match data.success {
            1 => Ok(data),
            _ => Err(PushError::ProcessingError("Success count in response is not 1".into())),
        }
    }))
}

#[cfg(test)]
mod test {
    use rustc_serialize::json;
    use super::*;

    #[test]
    fn test_priority_serialization() {
        assert_eq!(json::encode(&Priority::high).unwrap(), "\"high\"");
        assert_eq!(json::encode(&Priority::normal).unwrap(), "\"normal\"");
    }
}
