//! Code related to the sending of APNs push notifications.
//!
use std::convert::Into;
use std::io::Read;

use a2::client::{Client, Endpoint};
use a2::request::notification::{
    NotificationBuilder, NotificationOptions, Priority, SilentNotificationBuilder,
};
use futures::{future, Future};

use errors::{PushRelayError, SendPushError};
use push::{ApnsToken, ThreemaPayload, WakeupType};
use utils::SendFuture;


const PAYLOAD_KEY: &'static str = "3mw";


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
pub fn send_push<S: Into<String>>(
    client: &Client,
    push_token: &ApnsToken,
    bundle_id: S,
    version: u16,
    wakeup_type: WakeupType,
    session: &str,
) -> SendFuture<(), SendPushError> {
    // Notification options
    let options = NotificationOptions {
        apns_id: None,
        apns_expiration: Some(30),
        apns_priority: Priority::High,
        apns_topic: Some(bundle_id.into()),
        apns_collapse_id: None,
    };
    trace!("Notification options: {:#?}", options);

    // Notification payload
    let mut payload = SilentNotificationBuilder::new().build(&*push_token.0, options);
    let data = ThreemaPayload::new(session, version, wakeup_type.into());
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
                SendPushError::ProcessingError(format!("Push was unsuccessful: {}", error))
            })
    )
}
