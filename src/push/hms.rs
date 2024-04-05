//! Code related to the sending of HMS push notifications.
//!
//! ## Authentication
//!
//! We are using OAuth 2.0-based authentication with the "Client Credentials" mode.
//!
//! Docs: https://developer.huawei.com/consumer/en/doc/development/HMSCore-Guides/open-platform-oauth-0000001053629189
//!
//! ## Message Sending
//!
//! Docs: https://developer.huawei.com/consumer/en/doc/development/HMSCore-Guides/android-server-dev-0000001050040110
//!
//! Payload format: https://developer.huawei.com/consumer/en/doc/development/HMSCore-References-V5/https-send-api-0000001050986197-V5#EN-US_TOPIC_0000001124288117__section13271045101216

use std::{
    fmt::{self},
    str::{from_utf8, FromStr},
    time::{Duration, Instant},
};

use http::{
    header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE},
    Request, Response,
};
use hyper::{body, Body, StatusCode, Uri};
use serde_derive::{Deserialize, Serialize};
use serde_json as json;
use tokio::sync::Mutex;

use crate::{
    config::HmsConfig,
    errors::SendPushError,
    http_client::HttpClient,
    push::{HmsToken, ThreemaPayload},
};

enum EndpointType {
    Login,
    Push,
}

// Server endpoints
#[cfg(not(test))]
fn hms_endpoint(endpoint_type: EndpointType) -> &'static str {
    match endpoint_type {
        EndpointType::Login => "https://oauth-login.cloud.huawei.com",
        EndpointType::Push => "https://push-api.cloud.huawei.com",
    }
}
#[cfg(test)]
fn hms_endpoint(_: EndpointType) -> String {
    mockito::server_url()
}
fn hms_login_url() -> String {
    format!("{}/oauth2/v3/token", hms_endpoint(EndpointType::Login))
}
fn hms_push_url(app_id: &str) -> String {
    format!(
        "{}/v1/{}/messages:send",
        hms_endpoint(EndpointType::Push),
        app_id
    )
}

/// HMS push urgency.
#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Urgency {
    High,
    Normal,
}

/// HMS push category.
///
/// Note: To be able to use these categories, you need to apply for special
/// permission.
#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Category {
    //PlayVoice,
    Voip,
}

#[derive(Debug, Serialize)]
pub struct AndroidConfig {
    /// The urgency.
    urgency: Urgency,
    /// The push category.
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<Category>,
    /// Time to live in seconds.
    ttl: String,
}

#[derive(Debug, Serialize)]
pub struct Message<'a> {
    /// The push payload.
    data: String,
    /// Android message push control.
    android: AndroidConfig,
    /// Push token(s) of the recipient(s).
    token: &'a [&'a str],
}

/// HMS request body.
#[derive(Debug, Serialize)]
struct Payload<'a> {
    /// The message.
    message: Message<'a>,
}

/// HMS auth response.
#[derive(Debug, Deserialize)]
struct AuthResponse {
    access_token: String,
    expires_in: i32,
    token_type: String,
}

/// HMS auth response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushResponse {
    code: String,
    #[allow(dead_code)]
    msg: String,
    #[allow(dead_code)]
    request_id: String,
}

/// HMS service result code.
#[derive(Debug)]
enum HmsCode {
    Success,                       // 80000000
    SomeInvalidTokens,             // 80100000
    InvalidParameters,             // 80100001
    InvalidTokenCount,             // 80100002
    IncorrectMessageStructure,     // 80100003
    InvalidTtl,                    // 80100004
    InvalidCollapseKey,            // 80100013
    TooManyTopicMessages,          // 80100017
    AuthenticationError,           // 80200001
    AuthorizationExpired,          // 80200003
    PermissionDenied,              // 80300002
    InvalidTokens,                 // 80300007
    MessageTooLarge,               // 80300008
    TooManyTokens,                 // 80300010
    HighPriorityPermissionMissing, // 80300011
    InternalError,                 // 81000001
    Other(String),
}

impl fmt::Display for HmsCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const PREFIX: &str = "HMS push failed";
        match &self {
            &Self::Other(reason) => write!(f, "{} with unspecified code: {}", PREFIX, reason),
            _ => write!(f, "{}: {:?}", PREFIX, &self),
        }
    }
}

impl From<&str> for HmsCode {
    fn from(val: &str) -> Self {
        match val {
            "80000000" => Self::Success,

            "80100000" => Self::SomeInvalidTokens,
            "80100001" => Self::InvalidParameters,
            "80100002" => Self::InvalidTokenCount,
            "80100003" => Self::IncorrectMessageStructure,
            "80100004" => Self::InvalidTtl,
            "80100013" => Self::InvalidCollapseKey,
            "80100017" => Self::TooManyTopicMessages,

            "80200001" => Self::AuthenticationError,
            "80200003" => Self::AuthorizationExpired,

            "80300002" => Self::PermissionDenied,
            "80300007" => Self::InvalidTokens,
            "80300008" => Self::MessageTooLarge,
            "80300010" => Self::TooManyTokens,
            "80300011" => Self::HighPriorityPermissionMissing,

            "81000001" => Self::InternalError,

            _ => Self::Other(val.to_string()),
        }
    }
}

/// HMS OAuth2 credentials.
#[derive(Debug, Clone, PartialEq)]
pub struct HmsCredentials {
    /// The OAuth2 access token.
    access_token: String,

    /// Expiration of this access token.
    ///
    /// Note: We may set this to a time earlier than the actual token
    /// expiration.
    expiration: Instant,
}

impl HmsCredentials {
    /// Return true if the credentials are expired.
    pub fn expired(&self) -> bool {
        self.expiration <= Instant::now()
    }
}

impl From<AuthResponse> for HmsCredentials {
    fn from(resp: AuthResponse) -> Self {
        // Renew 180 seconds before expiration timestamp
        let expires_in = i32::max(resp.expires_in - 180, 0) as u64;
        Self {
            access_token: resp.access_token,
            expiration: Instant::now() + Duration::from_secs(expires_in),
        }
    }
}

/// The context object that holds state and authentication information.
#[derive(Debug)]
pub struct HmsContext {
    /// The HTTP client used to connect to HMS.
    client: HttpClient,

    /// The long-term credentials used to request temporary OAuth credentials.
    config: HmsConfig,

    /// The short-term credentials with a mutex, for exclusive access and
    /// interior mutability.
    credentials: Mutex<Option<HmsCredentials>>,
}

impl HmsContext {
    pub fn new(client: HttpClient, config: HmsConfig) -> Self {
        Self {
            client,
            config,
            credentials: Mutex::new(None),
        }
    }

    /// Request new OAuth2 credentials from the Huawei server.
    async fn request_new_credentials(&self) -> Result<HmsCredentials, SendPushError> {
        debug!("Requesting OAuth2 credentials");

        // Prepare request
        let body: String = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("client_secret", &self.config.client_secret)
            .finish();

        // Send request
        let request = Request::post(Uri::from_str(&hms_login_url()).unwrap())
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(CONTENT_LENGTH, &*body.len().to_string())
            .body(Body::from(body))
            .unwrap();
        let response: Response<Body> = self
            .client
            .request(request)
            .await
            .map_err(|e| SendPushError::AuthError(e.to_string()))?;

        // Extract status
        let status = response.status();

        // Fetch body
        let body_bytes = body::to_bytes(response.into_body()).await.map_err(|e| {
            SendPushError::AuthError(format!("Could not read HMS auth response body: {}", e))
        })?;

        // Validate status code
        if status != StatusCode::OK {
            match from_utf8(&body_bytes) {
                Ok(body) => warn!("OAuth2 response: HTTP {}: {}", status, body),
                Err(_) => warn!("OAuth2 response: HTTP {} (invalid UTF8 body)", status),
            }
            return Err(SendPushError::AuthError(format!(
                "Could not request HMS credentials: HTTP {}",
                status
            )));
        }
        trace!("OAuth2 response: HTTP {}", status);

        // Decode UTF8 bytes
        let json_body = from_utf8(&body_bytes).map_err(|_| {
            SendPushError::AuthError("Could not decode response JSON: Invalid UTF-8".into())
        })?;

        // Parse JSON
        let data: AuthResponse = json::from_str(json_body).map_err(|e| {
            SendPushError::AuthError(format!(
                "Could not decode response JSON: `{}` (Reason: {})",
                json_body, e
            ))
        })?;

        // Validate type
        if data.token_type != "Bearer" {
            warn!(
                "Returned OAuth2 token is of type '{}', not 'Bearer'",
                data.token_type
            );
        }

        Ok(data.into())
    }

    /// Return a copy of the HMS credentials.
    ///
    /// If there are no credentials so far, fetch and store them.
    /// If the credentials are outdated, refresh them.
    /// Otherwise, just return a copy directly.
    pub async fn get_active_credentials(&self) -> Result<HmsCredentials, SendPushError> {
        // Lock mutex
        let mut credentials = self.credentials.lock().await;

        match *credentials {
            // No credentials found, fetch initial credentials
            None => {
                let new_credentials = self.request_new_credentials().await?;
                *credentials = Some(new_credentials.clone());
                info!("Fetched initial OAuth credentials");
                Ok(new_credentials)
            }

            // Valid credentials found
            Some(ref credentials) if !credentials.expired() => {
                debug!(
                    "Credentials are still valid, expiration in {} seconds",
                    (credentials.expiration - Instant::now()).as_secs()
                );
                Ok(credentials.clone())
            }

            // Credentials must be renewed
            Some(_) => {
                let new_credentials = self.request_new_credentials().await?;
                *credentials = Some(new_credentials.clone());
                info!("Refreshed OAuth credentials");
                Ok(new_credentials)
            }
        }
    }

    /// Clear credentials
    pub async fn clear_credentials(&self) {
        info!("Clearing credentials");
        let mut credentials = self.credentials.lock().await;
        *credentials = None;
    }
}

/// Send a HMS push notification.
pub async fn send_push(
    context: &HmsContext,
    push_token: &HmsToken,
    version: u16,
    session: &str,
    affiliation: Option<&str>,
    ttl: u32,
) -> Result<(), SendPushError> {
    let threema_payload = ThreemaPayload::new(session, affiliation, version);
    let high_priority = context.config.high_priority.unwrap_or(false);
    let payload = Payload {
        message: Message {
            data: json::to_string(&threema_payload).expect("Could not encode JSON threema payload"),
            android: AndroidConfig {
                urgency: if high_priority {
                    Urgency::High
                } else {
                    Urgency::Normal
                },
                category: if high_priority {
                    Some(Category::Voip)
                } else {
                    None
                },
                ttl: format!("{}s", ttl),
            },
            token: &[&push_token.0],
        },
    };
    trace!("Sending payload: {:#?}", payload);

    // Encode payload
    let payload_string = json::to_string(&payload).expect("Could not encode JSON payload");
    debug!("Payload: {}", payload_string);

    // Get or refresh credentials
    let credentials = context.get_active_credentials().await?;

    // Prepare request
    let request = Request::post(Uri::from_str(&hms_push_url(&context.config.client_id)).unwrap())
        .header(CONTENT_TYPE, "application/json; charset=UTF-8")
        .header(CONTENT_LENGTH, &*payload_string.len().to_string())
        .header(
            AUTHORIZATION,
            &format!("Bearer {}", credentials.access_token),
        )
        .body(Body::from(payload_string))
        .unwrap();

    // Send request
    let response: Response<Body> = context
        .client
        .request(request)
        .await
        .map_err(|e| SendPushError::SendError(e.to_string()))?;

    // Extract status
    let status = response.status();

    // Fetch body
    let body_bytes = body::to_bytes(response.into_body()).await.map_err(|e| {
        SendPushError::AuthError(format!("Could not read HMS auth response body: {}", e))
    })?;

    // Decode UTF8 bytes
    let body = match from_utf8(&body_bytes) {
        Ok(string) => string,
        Err(_) => "[Non-UTF8 Body]", // This will fail to parse as JSON, but it's helpful for error logging
    };

    // Validate status code
    match status {
        StatusCode::OK => {
            trace!("HMS push request returned HTTP 200: {}", body);
        }
        StatusCode::BAD_REQUEST => {
            return Err(SendPushError::ProcessingClientError(format!(
                "Bad request: {}",
                body
            )));
        }
        StatusCode::INTERNAL_SERVER_ERROR | StatusCode::BAD_GATEWAY => {
            return Err(SendPushError::ProcessingRemoteError(format!(
                "HMS server error: {}",
                body
            )));
        }
        StatusCode::SERVICE_UNAVAILABLE => {
            return Err(SendPushError::ProcessingRemoteError(format!(
                "HMS quota reached: {}",
                body
            )));
        }
        _other => {
            return Err(SendPushError::Other(format!(
                "Unexpected status code: HTTP {}: {}",
                status, body
            )));
        }
    }

    // Parse JSON
    let data: PushResponse = json::from_str(body).map_err(|e| {
        SendPushError::Other(format!(
            "Could not decode response JSON: `{}` (Reason: {})",
            body, e
        ))
    })?;

    // Validate HMS code
    let code = HmsCode::from(&*data.code);
    match code {
        // Success
        HmsCode::Success => Ok(()),

        // Client errors
        HmsCode::SomeInvalidTokens | HmsCode::InvalidTokens => Err(
            SendPushError::ProcessingClientError("Invalid push token(s)".to_string()),
        ),

        // Potentially temporary errors
        HmsCode::InternalError => Err(SendPushError::ProcessingRemoteError(
            "HMS internal server error".to_string(),
        )),

        // Auth errors
        HmsCode::AuthenticationError | HmsCode::AuthorizationExpired => {
            // Clear credentials, since token may be invalid
            context.clear_credentials().await;
            Err(SendPushError::ProcessingRemoteError(format!(
                "Authentication error: {:?}",
                code
            )))
        }

        // Other errors
        other => Err(SendPushError::Other(format!("{}", other))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use mockito::mock;

    use crate::http_client;

    mod context {
        use super::*;

        #[tokio::test]
        async fn get_credentials() {
            const CLIENT_ID: &str = "klient";
            const CLIENT_SECRET: &str = "sehr-sekur";

            // Set up context
            let client = http_client::make_client(10);
            let context = HmsContext::new(
                client,
                HmsConfig {
                    client_id: CLIENT_ID.into(),
                    client_secret: CLIENT_SECRET.into(),
                    high_priority: None,
                },
            );

            // Mock HMS auth endpoint
            let m = mock("POST", "/oauth2/v3/token")
                .with_body(format!(
                    "grant_type=client_credentials&client_id={}&client_secret={}",
                    CLIENT_ID, CLIENT_SECRET
                ))
                .with_status(200)
                .with_body(
                    r#"{
                        "access_token": "akssess",
                        "expires_in": 3600,
                        "token_type": "Bearer"
                    }"#,
                )
                .create();

            // No credentials yet
            assert!(context.credentials.lock().await.is_none());

            // Get new credentials
            let credentials = context.get_active_credentials().await.unwrap();
            m.assert();
            assert!(context.credentials.lock().await.is_some());
            assert_eq!(credentials.access_token, "akssess");
            let remaining_validity = (credentials.expiration - Instant::now()).as_secs();
            assert!(remaining_validity <= (3600 - 180));
            assert!(remaining_validity > (3600 - 180 - 10));

            // Get cached credentials
            let credentials2 = context.get_active_credentials().await.unwrap();
            m.assert(); // This fails if the endpoint is called twice
            assert_eq!(credentials, credentials2);

            // Refresh credentials
            let m = m.expect(2);
            context
                .credentials
                .lock()
                .await
                .as_mut()
                .unwrap()
                .expiration = Instant::now() - Duration::from_secs(3);
            let credentials3 = context.get_active_credentials().await.unwrap();
            m.assert();
            let remaining_validity = (credentials3.expiration - Instant::now()).as_secs();
            assert!(remaining_validity > (3600 - 180 - 10));
        }
    }
}
