//! Code related to the sending of Threema Gateway push notifications.

use std::str;

use aead::AeadInPlace;
use crypto_secretbox::{
    XSalsa20Poly1305,
    aead::{AeadCore, KeyInit, OsRng},
};
use data_encoding::HEXLOWER;
use reqwest::{
    Client, StatusCode,
    header::{ACCEPT, CONTENT_TYPE},
};
use serde_json as json;
use x25519_dalek::StaticSecret;

use crate::{
    ThreemaGatewayPrivateKey,
    errors::SendPushError,
    push::{ThreemaPayload, threema_gateway::x25519::SharedSecretHSalsa20},
};

mod x25519 {
    use aead::generic_array::GenericArray;
    use salsa20::hsalsa;
    use x25519_dalek::SharedSecret;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct SharedSecretHSalsa20([u8; 32]);

    impl SharedSecretHSalsa20 {
        /// View this shared secret key as a byte array.
        #[inline]
        pub fn as_bytes(&self) -> &[u8; 32] {
            &self.0
        }
    }

    impl From<SharedSecret> for SharedSecretHSalsa20 {
        fn from(secret: SharedSecret) -> Self {
            // Use HSalsa20 to create a uniformly random key from the shared secret
            Self(
                hsalsa::<aead::consts::U10>(
                    GenericArray::from_slice(secret.as_bytes()),
                    &GenericArray::default(),
                )
                .into(),
            )
        }
    }
}

/// Send a Threema Gateway push notification.
pub async fn send_push(
    client: &Client,
    base_url: &str,
    secret: &str,
    from_identity: &str,
    private_key: ThreemaGatewayPrivateKey,
    to_identity: &str,
    public_key: [u8; 32],
    version: u16,
    session: &str,
    affiliation: Option<&str>,
) -> Result<(), SendPushError> {
    let payload = ThreemaPayload::new(session, affiliation, version, false);
    trace!("Sending payload: {:#?}", payload);

    // Encode and encrypt
    let (nonce, message) = {
        let private_key = StaticSecret::from(private_key.0);
        let shared_secret =
            SharedSecretHSalsa20::from(private_key.diffie_hellman(&public_key.into()));
        let cipher = XSalsa20Poly1305::new(shared_secret.as_bytes().into());
        let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng);
        let mut message: Vec<u8> = [
            // E2E message type
            &[0xfe],
            // Content
            json::to_vec(&payload)
                .expect("Could not encode JSON payload")
                .as_slice(),
            // No additional padding because it's kinda obvious what's being sent here by looking at the sender's
            // identity.
            &[0x01],
        ]
        .concat();
        cipher
            .encrypt_in_place(&nonce, b"", &mut message)
            .map_err(|_| SendPushError::Internal("Encryption failed".into()))?;
        (nonce, message)
    };

    // URL-encode (sigh)
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("secret", secret)
        .append_pair("from", from_identity)
        .append_pair("to", to_identity)
        .append_pair("noPush", "1")
        .append_pair("noDeliveryReceipts", "1")
        .append_pair("nonce", HEXLOWER.encode(nonce.as_slice()).as_str())
        .append_pair("box", HEXLOWER.encode(&message).as_str())
        .finish();

    // Send request
    let response = client
        .post(format!("{base_url}/send_e2e"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(ACCEPT, "application/json")
        .body(body)
        .send()
        .await
        .map_err(SendPushError::SendError)?;

    // Check status code
    match response.status() {
        StatusCode::OK => Ok(()),
        StatusCode::BAD_REQUEST => Err(SendPushError::RemoteServer(
            "Receiver identity invalid".into(),
        )),
        StatusCode::UNAUTHORIZED => Err(SendPushError::RemoteServer(
            "Unauthorized. Is the API secret correct?".into(),
        )),
        StatusCode::PAYMENT_REQUIRED => Err(SendPushError::RemoteServer("Out of credits".into())),
        StatusCode::PAYLOAD_TOO_LARGE => {
            Err(SendPushError::RemoteServer("Message too long".into()))
        }
        status => Err(SendPushError::Internal(format!(
            "Unknown error: Status {status}"
        ))),
    }
}
