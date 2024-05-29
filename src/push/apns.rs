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
            DefaultNotificationBuilder, NotificationBuilder, NotificationOptions, Priority,
        },
        payload::{APSAlert, APSSound, Payload, APS},
    },
    response::ErrorReason,
    ClientConfig, CollapseId, PushType,
};

use crate::{
    errors::{InitError, SendPushError},
    push::{ApnsToken, ThreemaPayload},
};

const PAYLOAD_KEY: &str = "3mw";

/// Create a new APNs client instance.
pub fn create_client<S>(
    endpoint: Endpoint,
    api_key: impl Read,
    team_id: S,
    key_id: S,
) -> Result<Client, InitError>
where
    S: Into<String>,
{
    let config = ClientConfig::new(endpoint);
    Client::token(api_key, key_id, team_id, config).map_err(InitError::Apns)
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

    // CHeck if it is a voip push
    let is_voip = bundle_id.ends_with(".voip");

    // Determine type of notification
    let apns_push_type = Some(if is_voip {
        PushType::Voip
    } else {
        PushType::Alert
    });

    // Notification options
    let options = NotificationOptions {
        apns_id: None,
        apns_expiration: expiration,
        apns_priority: Some(Priority::High),
        apns_topic: Some(bundle_id),
        apns_collapse_id: collapse_id,
        apns_push_type,
    };

    // Notification payload
    let mut payload = if is_voip {
        // This is a voip push, so use notification without body but `content-available` set to 1 to allow device wakeup
        // even though push is empty (silent notifications)
        DefaultNotificationBuilder::new()
            .set_content_available()
            .build(&push_token.0, options)
    } else {
        // Regular push, build notification ourselves for full control
        Payload {
            options,
            device_token: &push_token.0,
            aps: APS {
                alert: Some(APSAlert::Body("Threema Web Wakeup")),
                badge: None,
                sound: Some(APSSound::Sound("default")),
                content_available: None,
                category: None,
                mutable_content: Some(1),
                url_args: None,
            },
            data: BTreeMap::new(),
        }
    };

    let data = ThreemaPayload::new(session, affiliation, version, false);
    payload.add_custom_data(PAYLOAD_KEY, &data).map_err(|e| {
        SendPushError::Internal(format!("Could not add custom data to APNs payload: {}", e))
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
                            return Err(SendPushError::RemoteClient(
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
            Err(SendPushError::RemoteServer(format!(
                "Push was unsuccessful: {}",
                e
            )))
        }
    }
}
