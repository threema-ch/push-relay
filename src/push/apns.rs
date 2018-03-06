use apns2::client::Endpoint;
use futures::future;
use tokio_core::reactor::Handle;

use ::errors::PushError;
use ::push::ApnsToken;
use ::utils::BoxedFuture;


/// Send an APNS push notification.
///
/// TODO: Once the next release is out, remove Option around version.
#[allow(dead_code)]
pub fn send_push(
    _handle: Handle,
    _endpoint: Endpoint,
    _push_token: &ApnsToken,
    _version: u16,
    _session: &str,
) -> BoxedFuture<(), PushError> {
    boxed!(future::ok(()))
}
