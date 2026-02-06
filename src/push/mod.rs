pub mod apns;
pub mod fcm;
pub mod hms;
pub mod threema_gateway;

use chrono::Utc;
use serde::{Serialize, Serializer};

/// A FCM token.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FcmToken(pub String);

/// An APNs device token.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ApnsToken(pub String);

impl AsRef<str> for ApnsToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A HMS token.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HmsToken(pub String);

/// The possible push token types.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PushToken {
    Fcm(FcmToken),
    Apns(ApnsToken),
    Hms {
        token: HmsToken,
        app_id: String,
    },
    ThreemaGateway {
        identity: String,
        public_key: [u8; 32],
    },
}

impl PushToken {
    pub fn abbrev(&self) -> &'static str {
        match *self {
            PushToken::Fcm(_) => "FCM",
            PushToken::Apns(_) => "APNs",
            PushToken::Hms { .. } => "HMS",
            PushToken::ThreemaGateway { .. } => "ThreemaGateway",
        }
    }
}

impl AsRef<str> for FcmToken {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

/// Payload sent to end device inside the push notification.
#[derive(Debug, Serialize)]
pub(super) struct ThreemaPayload<'a> {
    /// Session id (public key of the initiator)
    #[serde(rename = "wcs")]
    session_id: &'a str,
    /// Affiliation id
    #[serde(rename = "wca", skip_serializing_if = "Option::is_none")]
    affiliation_id: Option<&'a str>,
    #[serde(flatten)]
    platform_specific_data: PlatformSpecificData,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
/// Data that does not have the same type on different platforms, although the fields are the same
enum PlatformSpecificData {
    /// Used for FCM only. Has to be key/value payload of type string:
    /// <https://firebase.google.com/docs/reference/fcm/rest/v1/projects.messages#AndroidConfig.FIELDS.data>
    AsString {
        /// Timestamp
        #[serde(rename = "wct", serialize_with = "serialize_as_str")]
        timestamp: i64,
        /// Version
        #[serde(rename = "wcv", serialize_with = "serialize_as_str")]
        version: u16,
    },
    /// Used for all platforms but FCM
    AsNumber {
        /// Timestamp
        #[serde(rename = "wct")]
        timestamp: i64,
        /// Version
        #[serde(rename = "wcv")]
        version: u16,
    },
}

fn serialize_as_str<S>(n: &impl ToString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&n.to_string())
}

impl<'a> ThreemaPayload<'a> {
    pub fn new(
        session_id: &'a str,
        affiliation_id: Option<&'a str>,
        version: u16,
        is_fcm_payload: bool,
    ) -> Self {
        let timestamp = Utc::now().timestamp();
        ThreemaPayload {
            session_id,
            affiliation_id,
            platform_specific_data: if is_fcm_payload {
                PlatformSpecificData::AsString { timestamp, version }
            } else {
                PlatformSpecificData::AsNumber { timestamp, version }
            },
        }
    }
}
