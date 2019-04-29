//! Code related to the sending of APNs push notifications.
//!
use std::convert::Into;
use std::io::Read;

use a2::CollapseId;
use a2::client::{Client, Endpoint};
use a2::error::{Error as A2Error};
use a2::request::notification::{
    NotificationBuilder, NotificationOptions, Priority, SilentNotificationBuilder,
};
use a2::response::ErrorReason;
use futures::{future, Future};

use crate::errors::{PushRelayError, SendPushError};
use crate::push::{ApnsToken, ThreemaPayload};
use crate::utils::SendFuture;


const PAYLOAD_KEY: &str = "3mw";


/// Create a new APNs client instance.
pub fn create_client<R, T, K>(
    endpoint: Endpoint,
    api_key: R,
    team_id: T,
    key_id: K,
) -> Result<Client, PushRelayError>
where
    R: Read,
    T: Into<String>,
    K: Into<String>,
{
    Client::token(api_key, key_id, team_id, endpoint).map_err(Into::into)
}

/// Send an APNs push notification.
pub fn send_push(
    client: &Client,
    push_token: &ApnsToken,
    bundle_id: &str,
    version: u16,
    session: &str,
    collapse_id: Option<CollapseId>,
    ttl: u32,
) -> SendFuture<(), SendPushError> {
    // Notification options
    let options = NotificationOptions {
        apns_id: None,
        apns_expiration: Some(u64::from(ttl)),
        apns_priority: Priority::High,
        apns_topic: Some(bundle_id),
        apns_collapse_id: collapse_id,
    };

    // Notification payload
    let mut payload = SilentNotificationBuilder::new().build(&*push_token.0, options);
    let data = ThreemaPayload::new(session, version);
    if let Err(e) = payload.add_custom_data(PAYLOAD_KEY, &data) {
        return Box::new(future::err(SendPushError::Other(format!(
            "Could not add custom data to APNs payload: {}",
            e
        ))));
    }
    trace!("Sending payload: {:#?}", payload);

    Box::new(
        client
            .send(payload)
            .map(|response| debug!("Success details: {:?}", response))
            .map_err(|error| {
                // Treat "bad device token" errors as client errors
                if let A2Error::ResponseError(ref resp) = error {
                    if let Some(ref body) = resp.error {
                        trace!("Response body: {:?}", body);
                        if body.reason == ErrorReason::BadDeviceToken {
                            return SendPushError::ProcessingClientError(
                                "Push was unsuccessful: Bad device token".to_string()
                            );
                        }
                    }
                }

                // Treat all other errors as server errors
                SendPushError::ProcessingRemoteError(format!("Push was unsuccessful: {}", error))
            })
    )
}
