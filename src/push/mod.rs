pub mod apns;
pub mod gcm;

use chrono::Utc;
use serde_derive::Serialize;


/// A GCM token.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct GcmToken(pub String);

/// An APNs device token.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ApnsToken(pub String);

/// The possible push token types.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PushToken {
    Gcm(GcmToken),
    Apns(ApnsToken),
}

impl PushToken {
    pub fn abbrev(&self) -> &'static str {
        match *self {
            PushToken::Gcm(_) => "GCM",
            PushToken::Apns(_) => "APNs",
        }
    }
}

/// Payload sent to end device inside the push notification.
#[derive(Debug, Serialize)]
struct ThreemaPayload<'a> {
    /// Session id (public key of the initiator)
    wcs: &'a str,
    /// Timestamp
    wct: i64,
    /// Version
    wcv: u16,
}

impl<'a> ThreemaPayload<'a> {
    pub fn new(session: &'a str, version: u16) -> Self {
        ThreemaPayload {
            wcs: session,
            wct: Utc::now().timestamp(),
            wcv: version,
        }
    }
}
