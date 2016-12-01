use std::io::Read;
use hyper::Client;
use hyper::header::{ContentType, Authorization};
use hyper::status::StatusCode;
use rustc_serialize::json;
use chrono::UTC;
use ::errors::PushError;

static GCM_ENDPOINT: &'static str = "https://android.googleapis.com/gcm/send";

#[derive(Debug, RustcEncodable)]
struct Data<'a> {
    /// Session id (public key of the initiator)
    wcs: &'a str,
    /// Timestamp
    wct: i64,
}

#[derive(Debug, RustcEncodable)]
struct Payload<'a> {
    to: &'a str,
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
pub fn send_push(api_key: &str, push_token: &str, session: &str) -> Result<MessageResponse, PushError> {
    let data = Data { wcs: session, wct: get_timestamp() };
    let payload = Payload { to: push_token, data: data };

    let client = Client::new();
    let payload = json::encode(&payload).expect("Could not encode JSON payload");
    let mut response = try!(client
        .post(GCM_ENDPOINT)
        .body(&payload)
        .header(Authorization(format!("key={}", api_key)))
        .header(ContentType::json())
        .send());

    let mut body = String::new();
    response.read_to_string(&mut body).unwrap();

    match response.status {
        StatusCode::Ok => {
            let data = try!(json::decode::<MessageResponse>(&body).map_err(|_| {
                PushError::Other(format!("Could not decode response JSON: {}", &body))
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
