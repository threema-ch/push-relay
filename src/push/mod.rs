pub mod gcm;


/// A GCM token.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct GcmToken(pub String);

/// An APNS device token.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ApnsToken(pub String);

/// The possible push token types.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PushToken {
    Gcm(GcmToken),
    Apns(ApnsToken),
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
