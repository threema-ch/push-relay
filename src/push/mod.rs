pub mod gcm;


/// The possible push token types.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PushToken {
    Gcm(String),
    Apns(String),
}

/// Payload sent to end device inside the push notification.
#[derive(Debug, Serialize)]
struct Data<'a> {
    /// Session id (public key of the initiator)
    wcs: &'a str,
    /// Timestamp
    wct: i64,
    /// Version
    wcv: u16,
}
