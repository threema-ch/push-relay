use std::io::Read;
use hyper::Client;
use hyper::header::{ContentType, Authorization};
use hyper::status::StatusCode;
use rustc_serialize::json;
use chrono::UTC;
use ::errors::PushError;

#[cfg(test)]
use mockito::SERVER_URL;

#[cfg(not(test))]
static GCM_ENDPOINT: &'static str = "https://android.googleapis.com";
#[cfg(test)]
static GCM_ENDPOINT: &'static str = SERVER_URL;
static GCM_PATH: &'static str = "/gcm/send";

#[derive(Debug, RustcEncodable)]
struct Data<'a> {
    /// Session id (public key of the initiator)
    wcs: &'a str,
    /// Timestamp
    wct: i64,
    /// Version
    wcv: u16,
}

#[derive(Debug, RustcEncodable)]
#[allow(non_camel_case_types)]
pub enum Priority {
    high,
    normal,
}

#[derive(Debug, RustcEncodable)]
struct Payload<'a> {
    to: &'a str,
    priority: Priority,
    time_to_live: u32,
    data: Data<'a>,
}

#[derive(Debug, RustcDecodable)]
pub struct MessageResult {
    pub message_id: String,
    pub registration_id: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, RustcDecodable)]
pub struct MessageResponse {
    pub multicast_id: i64,
    pub success: i64,
    pub failure: i64,
    pub canonical_ids: i64,
    pub results: Option<Vec<MessageResult>>,
}

/// Return the current unix epoch timestamp
fn get_timestamp() -> i64 {
    UTC::now().timestamp()
}

/// Send a push notification.
///
/// TODO: Once the next release is out, remove Option around version.
pub fn send_push(api_key: &str, push_token: &str, version: u16, session: &str,
                 priority: Priority, ttl: u32) -> Result<MessageResponse, PushError> {
    let data = Data { wcs: session, wct: get_timestamp(), wcv: version };
    let payload = Payload { to: push_token, priority: priority, time_to_live: ttl, data: data };

    let client = Client::new();
    let payload_string = json::encode(&payload).expect("Could not encode JSON payload");
    debug!("Payload: {}", payload_string);
    let url = GCM_ENDPOINT.to_string() + GCM_PATH;
    let mut response = try!(client
        .post(&url)
        .body(&payload_string)
        .header(Authorization(format!("key={}", api_key)))
        .header(ContentType::json())
        .send());

    let mut body = String::new();
    response.read_to_string(&mut body).unwrap();

    match response.status {
        StatusCode::Ok => {
            let data = try!(json::decode::<MessageResponse>(&body).map_err(|e| {
                PushError::Other(
                    format!("Could not decode response JSON: `{}` (Reason: {}", &body, e)
                )
            }));
            match data.success {
                1 => Ok(data),
                _ => Err(PushError::ProcessingError("Success count in response is not 1".into())),
            }
        },
        StatusCode::BadRequest => Err(PushError::ProcessingError("400 Bad Request".into())),
        StatusCode::Unauthorized => Err(PushError::ProcessingError("Unauthorized. Is the API token correct?".into())),
        _ => Err(PushError::Other(format!("Unknown error: {}", body))),
    }
}

#[cfg(test)]
mod test {
    use rustc_serialize::json;
    use super::*;

    #[test]
    fn test_priority_serialization() {
        assert_eq!(json::encode(&Priority::high).unwrap(), "\"high\"");
        assert_eq!(json::encode(&Priority::normal).unwrap(), "\"normal\"");
    }
}
