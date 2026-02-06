//! Code related to the sending of APNs push notifications.

use std::{
    convert::Into,
    io::Read,
    time::{Duration, SystemTime},
};

use apns_h2::{
    ClientConfig, CollapseId, PushType,
    client::{Client, Endpoint},
    error::Error as A2Error,
    request::notification::{
        DefaultNotificationBuilder, NotificationBuilder, NotificationOptions, Priority,
    },
    response::ErrorReason,
};

use crate::{
    errors::{InitError, SendPushError},
    push::{ApnsToken, ThreemaPayload},
};

const PAYLOAD_KEY: &str = "3mw";

#[derive(Clone)]
pub struct ApnsState {
    prod_client: Client,
    sandbox_client: Client,
}

impl ApnsState {
    pub fn new(prod_client: Client, sandbox_client: Client) -> Self {
        Self {
            prod_client,
            sandbox_client,
        }
    }

    pub fn get_for(&self, endpoint: Endpoint) -> &Client {
        match endpoint {
            Endpoint::Production => &self.prod_client,
            Endpoint::Sandbox => &self.sandbox_client,
        }
    }
}

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
            .content_available()
            .build(&push_token.0, options)
    } else {
        // Regular push, build notification ourselves for full control
        DefaultNotificationBuilder::new()
            .body("Threema Web Wakeup")
            .sound("default")
            .mutable_content()
            .build(push_token.0.as_str(), options)
    };

    let data = ThreemaPayload::new(session, affiliation, version, false);
    payload.add_custom_data(PAYLOAD_KEY, &data).map_err(|e| {
        SendPushError::Internal(format!("Could not add custom data to APNs payload: {e}"))
    })?;
    trace!("Sending payload: {:#?}", payload);

    match client.send(payload).await {
        Ok(response) => {
            debug!("Success details: {:?}", response);
            Ok(())
        }
        Err(e) => {
            if let A2Error::ResponseError(ref resp) = e
                && let Some(ref body) = resp.error
            {
                trace!("Response body: {:?}", body);
                match body.reason {
                        // Invalid device token
                        ErrorReason::ExpiredToken |
                        ErrorReason::BadDeviceToken |
                        ErrorReason::Unregistered |
                        // Key id of provider token does not match token or environment
                        ErrorReason::BadEnvironmentKeyIdInToken |
                        ErrorReason::UnrelatedKeyIdInToken |
                        // Invalid expiration date (invalid TTL)
                        ErrorReason::BadExpirationDate |
                        // Invalid topic (bundle id)
                        ErrorReason::BadTopic |
                        ErrorReason::DeviceTokenNotForTopic |
                        ErrorReason::TopicDisallowed => {
                            return Err(SendPushError::RemoteClient(
                                format!("Push was unsuccessful: {e}")));
                        },

                        // Below errors should never happen
                        ErrorReason::BadCollapseId |
                        ErrorReason::BadMessageId |
                        ErrorReason::BadPriority |
                        ErrorReason::DuplicateHeaders |
                        ErrorReason::Forbidden |
                        ErrorReason::IdleTimeout |
                        ErrorReason::InvalidPushType |
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

            // Treat all other errors as server errors
            Err(SendPushError::RemoteServer(format!(
                "Push was unsuccessful: {e}"
            )))
        }
    }
}
