//! Code related to the sending of GCM push notifications.

use std::str::{FromStr, from_utf8};

use futures::Stream;
use futures::future::{self, Future};
use http::{Request, Response};
use http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Body, Chunk, Client, StatusCode, Uri};
use hyper_tls::HttpsConnector;
use serde_derive::{Serialize, Deserialize};
use serde_json as json;

use crate::errors::SendPushError;
use crate::push::{GcmToken, ThreemaPayload};
use crate::utils::SendFuture;

#[cfg(test)]
use mockito::SERVER_URL;

#[cfg(not(test))]
static GCM_ENDPOINT: &'static str = "https://fcm.googleapis.com";

#[cfg(test)]
static GCM_ENDPOINT: &'static str = SERVER_URL;
static GCM_PATH: &'static str = "/fcm/send";


/// GCM push priority.
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub enum Priority {
    High,
    Normal,
}

/// GCM payload.
///
/// See <https://developers.google.com/cloud-messaging/http-server-ref>
#[derive(Debug, Serialize)]
struct Payload<'a> {
    to: &'a str,
    priority: Priority,
    time_to_live: u32,
    data: ThreemaPayload<'a>,
}

/// GCM push response.
#[derive(Debug, Deserialize)]
pub struct MessageResponse {
    pub multicast_id: i64,
    pub success: i64,
    pub failure: i64,
    pub canonical_ids: i64,
    pub results: Option<Vec<MessageResult>>,
}

/// GCM push result, sent inside the push response.
#[derive(Debug, Deserialize)]
pub struct MessageResult {
    pub message_id: String,
    pub registration_id: Option<String>,
    pub error: Option<String>,
}

/// Send a GCM push notification.
pub fn send_push(
    api_key: &str,
    push_token: &GcmToken,
    version: u16,
    session: &str,
    priority: Priority,
    ttl: u32,
) -> SendFuture<(), SendPushError> {
    let data = ThreemaPayload::new(session, version);
    let payload = Payload {
        to: &push_token.0,
        priority,
        time_to_live: ttl,
        data,
    };
    trace!("Sending payload: {:#?}", payload);

    // Create async HTTP client instance
    let https_connector = match HttpsConnector::new(4) {
        Ok(conn) => conn,
        Err(e) => {
            return Box::new(future::err(SendPushError::SendError(format!(
                "Could not create HttpsConnector: {}",
                e
            ))))
        },
    };
    let client = Client::builder().build(https_connector);

    // Encode payload
    let payload_string = json::to_string(&payload).expect("Could not encode JSON payload");
    debug!("Payload: {}", payload_string);

    // Build response future
    let response_future = client
        .request(
            Request::post(Uri::from_str(&(GCM_ENDPOINT.to_string() + GCM_PATH)).unwrap())
                .header(AUTHORIZATION, &*format!("key={}", api_key))
                .header(CONTENT_TYPE, "application/json")
                .header(CONTENT_LENGTH, &*payload_string.len().to_string())
                .body(Body::from(payload_string))
                .unwrap()
        )
        .map_err(|e| SendPushError::SendError(e.to_string()));

    let body_read_error = |e| SendPushError::Other(format!("Could not read GCM response body: {}", e));

    // Process response
    let chunk_future = response_future.and_then(move |response: Response<Body>| {
        // Future<Item=Chunk, Error=SendPushError>
        let status = response.status();
        let body = response.into_body();
        match status {
            StatusCode::OK => sboxed!(body.concat2().map_err(body_read_error)),
            StatusCode::BAD_REQUEST => sboxed!(future::err(SendPushError::ProcessingRemoteError("400 Bad Request".into()))),
            StatusCode::UNAUTHORIZED => sboxed!(future::err(SendPushError::ProcessingRemoteError("Unauthorized. Is the API token correct?".into()))),
            _ => sboxed!(
                body.concat2().map_err(body_read_error).and_then(
                    |chunk| match from_utf8(&*chunk) {
                        Ok(body) => Err(SendPushError::Other(format!("Unknown error: {}", body))),
                        Err(_) => Err(SendPushError::Other("Unknown error (and non-UTF-8 body)".into())),
                    },
                )
            ),
        }
    });

    // Process response body
    sboxed!(chunk_future.and_then(|chunk: Chunk| {
        // Decode UTF8 bytes
        let json_body = from_utf8(&*chunk).map_err(|_| {
            SendPushError::Other("Could not decode response JSON: Invalid UTF-8".into())
        })?;

        // Parse JSON
        let data = json::from_str::<MessageResponse>(json_body).map_err(|e| {
            SendPushError::Other(format!(
                "Could not decode response JSON: `{}` (Reason: {})",
                json_body, e
            ))
        })?;

        match data.success {
            1 => {
                trace!("Success details: {:?}", data);
                Ok(())
            },
            _ => Err(SendPushError::ProcessingRemoteError(
                "Success count in response is not 1".into(),
            )),
        }
    }))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_priority_serialization() {
        assert_eq!(json::to_string(&Priority::High).unwrap(), "\"high\"");
        assert_eq!(json::to_string(&Priority::Normal).unwrap(), "\"normal\"");
    }
}
