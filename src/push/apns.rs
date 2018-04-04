//! Code related to the sending of APNs push notifications.
//!
use std::convert::Into;
use std::io::Read;

use apns2::client::{Client, Endpoint};
use apns2::request::notification::{
    NotificationOptions, Priority, NotificationBuilder, SilentNotificationBuilder,
};
use futures::{future, Future};
use tokio_core::reactor::Handle;

use ::errors::PushError;
use ::push::{ApnsToken, ThreemaPayload};
use ::utils::BoxedFuture;


const PAYLOAD_KEY: &'static str = "3mw";


/// Create a new APNs client instance.
pub fn create_client<R, T, K>(
    handle: Handle,
    endpoint: Endpoint,
    api_key: R,
    team_id: T,
    key_id: K,
) -> Result<Client, PushError> where
    R: Read,
    T: Into<String>,
    K: Into<String>,
{
    Client::token(
        api_key,
        key_id,
        team_id,
        &handle,
        endpoint,
    ).map_err(Into::into)
}

/// Send an APNs push notification.
pub fn send_push<S: Into<String>>(
    client: &Client,
    push_token: &ApnsToken,
    bundle_id: S,
    version: u16,
    session: &str,
) -> BoxedFuture<(), PushError> {

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
    let data = ThreemaPayload::new(session, version);
    if let Err(e) = payload.add_custom_data(PAYLOAD_KEY, &data) {
        return boxed!(future::err(
            PushError::Other(format!("Could not add custom data to APNs payload: {}", e))
        ));
    }
    trace!("Sending payload: {:#?}", payload);

    boxed!(
        client
            .send(payload)
            .map(|response| debug!("Success details: {:?}", response))
            .map_err(|error| PushError::ProcessingError(format!("Push was unsuccessful: {}", error)))
    )
}
