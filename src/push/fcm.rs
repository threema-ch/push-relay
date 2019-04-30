//! Code related to the sending of FCM push notifications.

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
use crate::push::{FcmToken, ThreemaPayload};
use crate::utils::SendFuture;

#[cfg(test)]
use mockito::SERVER_URL;

#[cfg(not(test))]
static FCM_ENDPOINT: &'static str = "https://fcm.googleapis.com";

#[cfg(test)]
static FCM_ENDPOINT: &'static str = SERVER_URL;
static FCM_PATH: &'static str = "/fcm/send";


/// FCM push priority.
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub enum Priority {
    High,
    Normal,
}

/// FCM payload.
///
/// See <https://developers.google.com/cloud-messaging/http-server-ref>
#[derive(Debug, Serialize)]
struct Payload<'a> {
    to: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    collapse_key: Option<&'a str>,
    priority: Priority,
    time_to_live: u32,
    data: ThreemaPayload<'a>,
}

/// FCM push response.
#[derive(Debug, Deserialize)]
pub struct MessageResponse {
    pub multicast_id: i64,
    pub success: i64,
    pub failure: i64,
    pub canonical_ids: i64,
    pub results: Option<Vec<MessageResult>>,
}

/// FCM push result, sent inside the push response.
#[derive(Debug, Deserialize)]
pub struct MessageResult {
    pub message_id: Option<String>,
    pub registration_id: Option<String>,
    pub error: Option<String>,
}

/// Send a FCM push notification.
pub fn send_push(
    api_key: &str,
    push_token: &FcmToken,
    version: u16,
    session: &str,
    collapse_key: Option<&str>,
    priority: Priority,
    ttl: u32,
) -> SendFuture<(), SendPushError> {
    let data = ThreemaPayload::new(session, version);
    let payload = Payload {
        to: &push_token.0,
        collapse_key,
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
            Request::post(Uri::from_str(&(FCM_ENDPOINT.to_string() + FCM_PATH)).unwrap())
                .header(AUTHORIZATION, &*format!("key={}", api_key))
                .header(CONTENT_TYPE, "application/json")
                .header(CONTENT_LENGTH, &*payload_string.len().to_string())
                .body(Body::from(payload_string))
                .unwrap()
        )
        .map_err(|e| SendPushError::SendError(e.to_string()));

    let body_read_error = |e| SendPushError::Other(format!("Could not read FCM response body: {}", e));

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
        let data: MessageResponse = json::from_str(json_body).map_err(|e| {
            SendPushError::Other(format!(
                "Could not decode response JSON: `{}` (Reason: {})",
                json_body, e
            ))
        })?;

        match (data.success, data.failure) {
            (1, 0) => {
                trace!("Success details: {:?}", data);
                Ok(())
            }
            (0, 1) => {
                warn!("Response: {:?}", data);
                let msg: Option<String> = data.results
                    .and_then(|results| results.first().and_then(|result| result.error.clone()));
                Err(match msg.as_ref().map(String::as_str) {
                    // https://firebase.google.com/docs/cloud-messaging/http-server-ref#error-codes
                    Some("MissingRegistration") => SendPushError::ProcessingClientError("Push was unsuccessful: Missing push token".into()),
                    Some("InvalidRegistration") => SendPushError::ProcessingClientError("Push was unsuccessful: Invalid push token".into()),
                    Some("NotRegistered") => SendPushError::ProcessingClientError("Push was unsuccessful: Unregistered device".into()),
                    Some("InvalidPackageName") => SendPushError::ProcessingClientError("Push was unsuccessful: Push token does not match target app".into()),
                    Some("MismatchSenderId") => SendPushError::ProcessingClientError("Push was unsuccessful: Mismatched sender ID".into()),
                    Some("MessageTooBig") => SendPushError::ProcessingClientError("Push was unsuccessful: Message too big".into()),
                    Some("InvalidDataKey") => SendPushError::ProcessingClientError("Push was unsuccessful: Invalid data key".into()),
                    Some("InvalidTtl") => SendPushError::ProcessingClientError("Push was unsuccessful: Invalid TTL".into()),
                    Some("Unavailable") => SendPushError::ProcessingRemoteError("Push was unsuccessful: Timeout".into()),
                    Some("InternalServerError") => SendPushError::ProcessingRemoteError("Push was unsuccessful: Internal server error".into()),
                    Some("DeviceMessageRateExceeded") => SendPushError::ProcessingRemoteError("Push was unsuccessful: Device message rate exceeded".into()),
                    Some("TopicsMessageRateExceeded") => SendPushError::ProcessingRemoteError("Push was unsuccessful: Topics message rate exceeded".into()),
                    Some(other) => SendPushError::Other(format!("Push was unsuccessful: {}", other)),
                    None => SendPushError::Other("Push was unsuccessful".into()),
                })
            }
            (success, failure) => {
                warn!("Response: {:?}", data);
                Err(SendPushError::ProcessingRemoteError(format!(
                    "Unexpected payload: {} success {} failure responses",
                    success, failure
                )))
            }
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
