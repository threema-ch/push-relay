//! Code related to the sending of APNs push notifications.

use std::{
    collections::BTreeMap,
    convert::Into,
    io::Read,
    time::{Duration, SystemTime},
};

use a2::{
    client::{Client, Endpoint},
    error::Error as A2Error,
    request::{
        notification::{
            NotificationBuilder, NotificationOptions, Priority, SilentNotificationBuilder,
        },
        payload::{APSAlert, Payload, APS},
    },
    response::ErrorReason,
    CollapseId,
};

use crate::{
    errors::{PushRelayError, SendPushError},
    push::{ApnsToken, ThreemaPayload},
};

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
pub async fn send_push(
    client: &Client,
    push_token: &ApnsToken,
    bundle_id: &str,
    version: u16,
    session: &str,
    affiliation: Option<&str>,
    collapse_id: Option<CollapseId<'_>>,
    ttl: u32,
) -> Result<(), SendPushError> {
    // Note: This will swallow any errors when converting to a timestamp
    let expiration: Option<u64> = match ttl {
        0 => Some(0),
        ttl => {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Could not retrieve UNIX timestamp");
            now.checked_add(Duration::from_secs(u64::from(ttl)))
                .map(|expiration| expiration.as_secs())
        }
    };

    // Notification options
    let options = NotificationOptions {
        apns_id: None,
        apns_expiration: expiration,
        apns_priority: Some(Priority::High),
        apns_topic: Some(bundle_id),
        apns_collapse_id: collapse_id,
    };

    // Notification payload
    let mut payload = if bundle_id.ends_with(".voip") {
        // This is a voip push, so use the SilentNotificationBuilder
        SilentNotificationBuilder::new().build(&*push_token.0, options)
    } else {
        // Regular push, build notification ourselves for full control
        Payload {
            options,
            device_token: &*push_token.0,
            aps: APS {
                alert: Some(APSAlert::Plain("Threema Web Wakeup")),
                badge: None,
                sound: Some("default"),
                content_available: None,
                category: None,
                mutable_content: Some(1),
                url_args: None,
            },
            data: BTreeMap::new(),
        }
    };

    let data = ThreemaPayload::new(session, affiliation, version);
    payload.add_custom_data(PAYLOAD_KEY, &data).map_err(|e| {
        SendPushError::Other(format!("Could not add custom data to APNs payload: {}", e))
    })?;
    trace!("Sending payload: {:#?}", payload);

    match client.send(payload).await {
        Ok(response) => {
            debug!("Success details: {:?}", response);
            Ok(())
        }
        Err(e) => {
            if let A2Error::ResponseError(ref resp) = e {
                if let Some(ref body) = resp.error {
                    trace!("Response body: {:?}", body);
                    match body.reason {
                        // Invalid device token
                        ErrorReason::BadDeviceToken |
                        ErrorReason::Unregistered |
                        // Invalid expiration date (invalid TTL)
                        ErrorReason::BadExpirationDate |
                        // Invalid topic (bundle id)
                        ErrorReason::BadTopic |
                        ErrorReason::DeviceTokenNotForTopic |
                        ErrorReason::TopicDisallowed => {
                            return Err(SendPushError::ProcessingClientError(
                                format!("Push was unsuccessful: {}", e)));
                        },

                        // Below errors should never happen
                        ErrorReason::BadCollapseId |
                        ErrorReason::BadMessageId |
                        ErrorReason::BadPriority |
                        ErrorReason::DuplicateHeaders |
                        ErrorReason::Forbidden |
                        ErrorReason::IdleTimeout |
                        ErrorReason::MissingDeviceToken |
                        ErrorReason::MissingTopic |
                        ErrorReason::PayloadEmpty |
                        ErrorReason::BadCertificate |
                        ErrorReason::BadCertificateEnvironment |
                        ErrorReason::ExpiredProviderToken |
                        ErrorReason::InvalidProviderToken |
                        ErrorReason::MissingProviderToken |
                        ErrorReason::BadPath |
                        ErrorReason::MethodNotAllowed |
                        ErrorReason::PayloadTooLarge |
                        ErrorReason::TooManyProviderTokenUpdates => {
                            error!("Unexpected APNs error response: {}", e);
                        },

                        // APNs server errors
                        ErrorReason::TooManyRequests |
                        ErrorReason::InternalServerError |
                        ErrorReason::ServiceUnavailable |
                        ErrorReason::Shutdown => {}
                    };
                }
            }

            // Treat all other errors as server errors
            Err(SendPushError::ProcessingRemoteError(format!(
                "Push was unsuccessful: {}",
                e
            )))
        }
    }
}
