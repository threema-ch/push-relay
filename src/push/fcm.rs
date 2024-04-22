//! Code related to the sending of FCM push notifications.

use std::{str::from_utf8, sync::Arc};

use reqwest::{
    header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE},
    Client, StatusCode,
};
use serde_derive::{Deserialize, Serialize};
use serde_json as json;

use crate::{
    config::FcmConfig,
    errors::SendPushError,
    push::{FcmToken, ThreemaPayload},
};

pub const FCM_ENDPOINT: &str = "https://fcm.googleapis.com";

pub const FCM_PATH: &str = "/fcm/send";

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

#[derive(Debug)]
pub struct FcmStateConfig {
    api_key: String,
    endpoint: String,
}

impl FcmStateConfig {
    pub fn new_shared(config: FcmConfig, endpoint: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            api_key: config.api_key,
            endpoint: endpoint.into(),
        })
    }
}

/// Send a FCM push notification.
pub async fn send_push(
    client: &Client,
    config: &Arc<FcmStateConfig>,
    push_token: &FcmToken,
    version: u16,
    session: &str,
    affiliation: Option<&str>,
    collapse_key: Option<&str>,
    ttl: u32,
) -> Result<(), SendPushError> {
    let data = ThreemaPayload::new(session, affiliation, version);
    let payload = Payload {
        to: &push_token.0,
        collapse_key,
        priority: Priority::High,
        time_to_live: ttl,
        data,
    };
    trace!("Sending payload: {:#?}", payload);

    // Encode payload
    let payload_string = json::to_string(&payload).expect("Could not encode JSON payload");
    debug!("Payload: {}", payload_string);

    // Send request
    let response = client
        .post(format!("{}{}", config.endpoint.as_str(), FCM_PATH))
        .header(AUTHORIZATION, &*format!("key={}", config.api_key))
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, &*payload_string.len().to_string())
        .body(payload_string)
        .send()
        .await
        .map_err(|e| SendPushError::SendError(e.to_string()))?;

    // Read fully body
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|e| SendPushError::Other(format!("Could not read FCM response body: {}", e)))?;

    // Check status code
    match status {
        StatusCode::OK => {}
        StatusCode::BAD_REQUEST => {
            return Err(SendPushError::ProcessingRemoteError(
                "400 Bad Request".into(),
            ))
        }
        StatusCode::UNAUTHORIZED => {
            return Err(SendPushError::ProcessingRemoteError(
                "Unauthorized. Is the API token correct?".into(),
            ))
        }
        status => match from_utf8(&body) {
            Ok(body) => {
                return Err(SendPushError::Other(format!(
                    "Unknown error: HTTP {}: {}",
                    status, body
                )))
            }
            Err(_) => {
                return Err(SendPushError::Other(format!(
                    "Unknown error (and non-UTF-8 body): HTTP {}",
                    status
                )))
            }
        },
    }

    // Decode UTF8 bytes
    let json_body = from_utf8(&body).map_err(|_| {
        SendPushError::Other("Could not decode response JSON: Invalid UTF-8".into())
    })?;

    // Parse JSON
    let data: MessageResponse = json::from_str(json_body).map_err(|e| {
        SendPushError::Other(format!(
            "Could not decode response JSON: `{}` (Reason: {})",
            json_body, e
        ))
    })?;

    // Handle response data
    match (data.success, data.failure) {
        (1, 0) => {
            trace!("Success details: {:?}", data);
            Ok(())
        }
        (0, 1) => {
            debug!("Response: {:?}", data);
            let msg: Option<String> = data
                .results
                .and_then(|results| results.first().and_then(|result| result.error.clone()));
            Err(match msg.as_deref() {
                // https://firebase.google.com/docs/cloud-messaging/http-server-ref#error-codes
                Some("MissingRegistration") => SendPushError::ProcessingClientError(
                    "Push was unsuccessful: Missing push token".into(),
                ),
                Some("InvalidRegistration") => SendPushError::ProcessingClientError(
                    "Push was unsuccessful: Invalid push token".into(),
                ),
                Some("NotRegistered") => SendPushError::ProcessingClientError(
                    "Push was unsuccessful: Unregistered device".into(),
                ),
                Some("InvalidPackageName") => SendPushError::ProcessingClientError(
                    "Push was unsuccessful: Push token does not match target app".into(),
                ),
                Some("MismatchSenderId") => SendPushError::ProcessingClientError(
                    "Push was unsuccessful: Mismatched sender ID".into(),
                ),
                Some("MessageTooBig") => SendPushError::ProcessingClientError(
                    "Push was unsuccessful: Message too big".into(),
                ),
                Some("InvalidDataKey") => SendPushError::ProcessingClientError(
                    "Push was unsuccessful: Invalid data key".into(),
                ),
                Some("InvalidTtl") => SendPushError::ProcessingClientError(
                    "Push was unsuccessful: Invalid TTL".into(),
                ),
                Some("Unavailable") => {
                    SendPushError::ProcessingRemoteError("Push was unsuccessful: Timeout".into())
                }
                Some("InternalServerError") => SendPushError::ProcessingRemoteError(
                    "Push was unsuccessful: Internal server error".into(),
                ),
                Some("DeviceMessageRateExceeded") => SendPushError::ProcessingRemoteError(
                    "Push was unsuccessful: Device message rate exceeded".into(),
                ),
                Some("TopicsMessageRateExceeded") => SendPushError::ProcessingRemoteError(
                    "Push was unsuccessful: Topics message rate exceeded".into(),
                ),
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
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_priority_serialization() {
        assert_eq!(json::to_string(&Priority::High).unwrap(), "\"high\"");
        assert_eq!(json::to_string(&Priority::Normal).unwrap(), "\"normal\"");
    }

    impl FcmStateConfig {
        pub fn stub_with(endpoint: Option<String>) -> Arc<Self> {
            Arc::new(FcmStateConfig {
                api_key: "invalid fcm api key".to_owned(),
                endpoint: endpoint.unwrap_or_else(|| "invalid-fcm.endpoint".to_owned()),
            })
        }
    }
}
