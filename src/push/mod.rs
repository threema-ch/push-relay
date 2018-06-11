pub mod apns;
pub mod gcm;

use chrono::Utc;


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

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum WakeupType {
    /// A full reconnect (by entering the password on the main screen).
    FullReconnect,
    /// A wakeup, as implemented by the iOS app.
    Wakeup,
}

impl Into<u8> for WakeupType {
    fn into(self) -> u8 {
        match self {
            WakeupType::FullReconnect => 0,
            WakeupType::Wakeup => 1,
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
    /// Wakeup type
    wcw: u8,
}

impl<'a> ThreemaPayload<'a> {
    pub fn new(session: &'a str, version: u16, wakeup_type: u8) -> Self {
        ThreemaPayload {
            wcs: session,
            wct: Utc::now().timestamp(),
            wcv: version,
            wcw: wakeup_type,
        }
    }
}
