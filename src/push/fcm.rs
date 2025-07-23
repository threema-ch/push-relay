//! Code related to the sending of FCM push notifications.

use std::{borrow::Cow, sync::Arc, time::Duration};

use anyhow::Context;
use futures::{future::BoxFuture, Future, FutureExt};
use rand::Rng;
use reqwest::{
    header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, RETRY_AFTER},
    tls, Client as HttpClient, StatusCode,
};
use serde::{Deserialize, Serialize as DeriveSerialize, Serialize, Serializer};

use yup_oauth2::{authenticator::DefaultAuthenticator, AccessToken, ServiceAccountAuthenticator};

use crate::{
    config::{self, FcmApplicationSecret},
    errors::SendPushError,
};

pub const FCM_ENDPOINT: &str = "https://fcm.googleapis.com";
const FCM_TIMEOUT_SECS: u64 = 10;
const DEFAULT_RETRY_AFTER_MILLIS: u64 = 60 * 1000;

pub fn get_push_retry_calculator() -> &'static impl CalculatePushSleep {
    #[cfg(test)]
    {
        static MOCK_CALC: test::PushSleepSimulator = test::PushSleepSimulator;
        &MOCK_CALC
    }
    #[cfg(not(test))]
    {
        static CALC: PushSleepCalculator = PushSleepCalculator;
        &CALC
    }
}

/// FCM push priority.
#[derive(Debug, DeriveSerialize, Default)]
#[serde(rename_all = "UPPERCASE")]
#[allow(dead_code)]
pub enum Priority {
    #[default]
    High,
    Normal,
}

/// FCM push response.
#[derive(Debug, Deserialize)]
pub struct MessageResponse {
    name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    error: FcmError,
}

#[derive(Debug, Deserialize, Serialize)]
struct FcmError {
    code: u16,
    details: Option<Vec<ErrorDetails>>,
    message: Option<String>,
    status: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ErrorDetails {
    #[serde(rename = "@type")]
    error_type: Option<String>,
    #[serde(rename = "fieldViolations")]
    violations: Option<Vec<ErrorViolations>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ErrorViolations {
    description: Option<String>,
    field: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FcmEndpointConfig {
    /// Number of retries that will be made if a request fails in a recoverable way
    max_retries: u8,
    /// Full URL where the FCM requests will be sent to
    endpoint: String,
}

fn get_fcm_uri(project_id: &str, fcm_authority: impl AsRef<str>) -> String {
    let base_url = fcm_authority.as_ref();
    format!("{base_url}/v1/projects/{project_id}/messages:send")
}

impl FcmEndpointConfig {
    fn new(config: &config::FcmConfig, fcm_authority: impl AsRef<str>) -> Self {
        let endpoint = get_fcm_uri(&config.project_id, fcm_authority);
        Self {
            max_retries: config.max_retries,
            endpoint,
        }
    }
}

#[derive(Clone)]
pub struct FcmState<R>
where
    R: RequestOauthToken,
{
    config: FcmEndpointConfig,
    client: HttpClient,
    token_obtainer: R,
}

fn create_fcm_http_client() -> anyhow::Result<HttpClient> {
    #[allow(unused_mut)]
    let mut builder = HttpClient::builder()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_proxy()
        // https://firebase.google.com/docs/cloud-messaging/scale-fcm#timeouts
        .timeout(Duration::from_secs(FCM_TIMEOUT_SECS))
        .pool_idle_timeout(None)
        .min_tls_version(tls::Version::TLS_1_2);

    #[cfg(not(test))]
    {
        builder = builder.http2_prior_knowledge().https_only(true);
    }

    builder.build().context("Could not build fcm http client")
}

impl<T> FcmState<T>
where
    T: RequestOauthToken,
{
    pub async fn new(
        config: &config::FcmConfig,
        fcm_authority: Option<String>,
        token_obtainer: T,
    ) -> anyhow::Result<Self> {
        // Create FCM HTTP client
        let client = create_fcm_http_client()?;

        let fcm_authority = fcm_authority
            .map(Cow::Owned)
            .unwrap_or_else(|| Cow::Borrowed(FCM_ENDPOINT));

        Ok(Self {
            config: FcmEndpointConfig::new(config, fcm_authority),
            client,
            token_obtainer,
        })
    }
}

pub trait OauthToken: Send {
    fn token(&self) -> Option<&'_ str>;
}

pub trait RequestOauthToken: Sized + Send + Sync + Clone {
    async fn new(application_secret: &FcmApplicationSecret) -> anyhow::Result<Self>;
    fn request_token(
        &self,
    ) -> impl Future<Output = Result<impl OauthToken, SendPushError>> + std::marker::Send;
}

#[derive(Clone)]
pub struct HttpOauthTokenObtainer {
    oauth_authenticator: DefaultAuthenticator,
}

struct FcmAccessToken {
    access_token: AccessToken,
}

impl OauthToken for FcmAccessToken {
    fn token(&self) -> Option<&'_ str> {
        self.access_token.token()
    }
}

impl RequestOauthToken for HttpOauthTokenObtainer {
    async fn request_token(&self) -> Result<impl OauthToken, SendPushError> {
        const SCOPES: [&str; 1] = ["https://www.googleapis.com/auth/firebase.messaging"];

        let access_token = self.oauth_authenticator.token(&SCOPES).await.map_err(|e| {
            SendPushError::RemoteAuth(format!("Could not retrieve bearer token: {e}"))
        })?;
        Ok(FcmAccessToken { access_token })
    }

    async fn new(application_secret: &FcmApplicationSecret) -> anyhow::Result<Self> {
        let service_account_key = yup_oauth2::parse_service_account_key(application_secret)
            .map_err(|e| SendPushError::Internal(format!("Could not read fcm json secret: {e}")))
            .context("Failed to read application secret")?;
        let oauth_authenticator = ServiceAccountAuthenticator::builder(service_account_key)
            .build()
            .await
            .map_err(|e| {
                SendPushError::Internal(format!("Could not initialize OAuth 2.0 client: {e}"))
            })
            .context("Could not build oauth authenticator")?;
        Ok(Self {
            oauth_authenticator,
        })
    }
}

/// Trait for implementing the time that is waited between subsequent push attempts
pub trait CalculatePushSleep: Sized + Send + Sync {
    /// Calculate the number of milliseconds that are waited until a retry of the push send is attempted.
    ///
    /// Exponential backoff with jittering will be applied to calculate the sleep duration. See
    /// <https://firebase.google.com/docs/cloud-messaging/scale-fcm> for further information.
    fn calculate_retry_sleep_millis(&self, try_counter: u8) -> u64;
}

#[derive(Debug, Clone, Copy)]
pub struct AndroidTtlSeconds(u32);

impl Default for AndroidTtlSeconds {
    fn default() -> Self {
        // Two weeks in seconds
        Self(2 * 7 * 24 * 3600)
    }
}

impl AndroidTtlSeconds {
    pub fn new(ttl: u32) -> Self {
        Self(ttl)
    }
}

#[derive(Debug, DeriveSerialize)]
pub struct HttpV1Payload<'a, S: Serialize + Send> {
    /// See [`Message`] for docs
    message: Message<'a, S>,
}

impl<'a, S> HttpV1Payload<'a, S>
where
    S: Serialize + Send,
{
    pub fn new(
        android_ttl: AndroidTtlSeconds,
        registration_id: &'a str,
        payload: &'a S,
        collapse_key: Option<&'a str>,
    ) -> Self {
        Self {
            message: Message::new(android_ttl, registration_id, payload, collapse_key),
        }
    }
}

/// JSON specification of Message payload: <https://firebase.google.com/docs/reference/fcm/rest/v1/projects.messages#resource:-message>
#[derive(Debug, DeriveSerialize)]
struct Message<'a, S: Serialize> {
    #[serde(rename = "token")]
    registration_id: &'a str,
    data: &'a S,
    #[serde(rename = "android")]
    android_config: AndroidConfig<'a>,
}

impl<'a, S> Message<'a, S>
where
    S: Serialize,
{
    fn new(
        android_ttl: AndroidTtlSeconds,
        registration_id: &'a str,
        data: &'a S,
        collapse_key: Option<&'a str>,
    ) -> Self {
        Self {
            registration_id,
            data,
            android_config: AndroidConfig::new(android_ttl, collapse_key),
        }
    }
}

#[derive(Debug, Serialize, Default)]
struct AndroidConfig<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    collapse_key: Option<&'a str>,
    priority: Priority,
    #[serde(serialize_with = "serialize_android_ttl")]
    ttl: AndroidTtlSeconds,
}

fn serialize_android_ttl<S>(ttl: &AndroidTtlSeconds, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{}s", ttl.0))
}

impl<'a> AndroidConfig<'a> {
    fn new(ttl: AndroidTtlSeconds, collapse_key: Option<&'a str>) -> Self {
        Self {
            ttl,
            collapse_key,
            ..Default::default()
        }
    }
}

/// Send a FCM push notification.
pub fn send_push<'a>(
    state: Arc<FcmState<impl RequestOauthToken + 'a>>,
    retry_calculator: &'static impl CalculatePushSleep,
    http_payload: HttpV1Payload<'a, impl Serialize + Send + Sync>,
    try_counter: u8,
) -> BoxFuture<'a, Result<u16, SendPushError>> {
    async move { _send_push(state, retry_calculator, http_payload, try_counter).await }.boxed()
}

pub struct PushSleepCalculator;

impl CalculatePushSleep for PushSleepCalculator {
    fn calculate_retry_sleep_millis(&self, try_counter: u8) -> u64 {
        // 2 to the power of `try_counter_` will be used as base value for exponential backoff. `+-8%` of deviation
        // will be added or subtracted so that the retries are not scheduled at the same time.
        let sleep_millis = 2u64.pow(try_counter.into()) * 1000;
        let deviation = sleep_millis / 100 * 8;
        rand::thread_rng().gen_range((sleep_millis - deviation)..(sleep_millis + deviation))
    }
}

fn can_push_be_retried(code: StatusCode) -> bool {
    let http_code = code.as_u16();
    http_code == 429 || http_code >= 500
}

/// # Note
/// Don't call this directly, call [`send_push`] instead!
async fn _send_push(
    state: Arc<FcmState<impl RequestOauthToken>>,
    retry_calculator: &'static impl CalculatePushSleep,
    http_payload: HttpV1Payload<'_, impl Serialize + Send + Sync>,
    try_counter: u8,
) -> Result<u16, SendPushError> {
    if try_counter != 0 {
        debug!("Retry #{}", try_counter);
    }

    let payload_string = serde_json::ser::to_string_pretty(&http_payload)
        .map_err(|e| SendPushError::Internal(format!("Could not encode JSON payload: {e}")))?;

    let response = {
        // Acquire token
        let access_token = state.token_obtainer.request_token().await?;
        let access_token_str = access_token.token().ok_or_else(|| {
            SendPushError::RemoteAuth("No bearer token present after retrieving it".to_string())
        })?;

        // Send request
        state
            .client
            .post(&state.config.endpoint)
            .header(AUTHORIZATION, format!("Bearer {}", access_token_str))
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, payload_string.len().to_string())
            .body(payload_string)
            .send()
            .await
            .map_err(SendPushError::SendError)?
    };

    // Get retry-after header if it is present
    let retry_after_secs = response.headers().get(RETRY_AFTER).map(|value| {
        value
            .to_str()
            .context("No ascii string")
            .and_then(|a| str::parse::<u64>(a).context("No u64"))
    });

    // Transform response into body
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|e| SendPushError::Internal(format!("Could not read FCM response body: {e}")))?;

    // Check status code
    let status_code = status.as_u16();
    // Error reference: <https://firebase.google.com/docs/cloud-messaging/scale-fcm#errors>
    match status {
        // https://firebase.google.com/docs/cloud-messaging/manage-tokens#detect-invalid-token-responses-from-the-fcm-backend
        StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND => {
            return Err(SendPushError::RemoteClient(format!(
                "Token or payload is invalid: HTTP {status_code}"
            )));
        }
        StatusCode::UNAUTHORIZED | StatusCode::PAYMENT_REQUIRED => {
            return Err(SendPushError::RemoteClient(format!(
                "Unrecoverable error code received: HTTP {status_code}"
            )))
        }
        status if can_push_be_retried(status) => {
            if try_counter >= state.config.max_retries {
                return Err(SendPushError::RemoteServer(format!(
                    "Max push retry count has been reached. Last HTTP status: {status_code}"
                )));
            }

            let sleep_time_millis = match retry_after_secs {
                Some(Ok(secs)) => secs * 1000,
                Some(Err(e)) => {
                    info!("Could not parse \"retry-after\": {}", e);
                    DEFAULT_RETRY_AFTER_MILLIS
                }
                None => retry_calculator.calculate_retry_sleep_millis(try_counter),
            };

            tokio::time::sleep(Duration::from_millis(sleep_time_millis)).await;
            debug!("Retrying to send push after {} ms", sleep_time_millis);

            return send_push(state, retry_calculator, http_payload, try_counter + 1).await;
        }
        // Catch all error codes that cannot be retried
        _ if status_code >= 300 => {
            return Err(SendPushError::RemoteServer(format!(
                "Unknown http error code: HTTP {status_code}"
            )))
        }
        _ => trace!("HTTP status code: {}", status_code),
    }

    // Decode UTF8 bytes
    let json_body = std::str::from_utf8(&body).map_err(|_| {
        SendPushError::Internal("Could not decode response JSON: Invalid UTF-8".into())
    })?;

    // Parse JSON
    let data: MessageResponse = serde_json::de::from_str(json_body)
        .map_err(|e| SendPushError::Internal(format!("Could not decode response JSON: {e}")))?;

    debug!("Sent push message: {}", data.name);

    Ok(status_code)
}

#[cfg(test)]
pub mod test {
    use super::*;

    pub fn get_fcm_test_path(config: &config::FcmConfig) -> String {
        get_fcm_uri(&config.project_id, "")
    }

    #[derive(Clone)]
    pub struct MockAccessTokenObtainer;
    pub struct MockAccessToken;

    impl OauthToken for MockAccessToken {
        fn token(&self) -> Option<&'_ str> {
            Some("fake-access-token")
        }
    }

    impl RequestOauthToken for MockAccessTokenObtainer {
        async fn new(_: &FcmApplicationSecret) -> anyhow::Result<Self> {
            Ok(MockAccessTokenObtainer)
        }

        async fn request_token(&self) -> Result<impl OauthToken, SendPushError> {
            Ok(MockAccessToken)
        }
    }

    pub struct PushSleepSimulator;

    impl CalculatePushSleep for PushSleepSimulator {
        fn calculate_retry_sleep_millis(&self, _try_counter: u8) -> u64 {
            0
        }
    }

    #[test]
    fn test_priority_serialization() {
        assert_eq!(serde_json::to_string(&Priority::High).unwrap(), "\"HIGH\"");
        assert_eq!(
            serde_json::to_string(&Priority::Normal).unwrap(),
            "\"NORMAL\""
        );
    }

    pub fn get_fcm_error(
        code: StatusCode,
        message: &str,
        status_code_uppercase: &str,
    ) -> ErrorResponse {
        ErrorResponse {
            error: FcmError {
                code: code.as_u16(),
                details: Some(vec![ErrorDetails {
                    error_type: Some("type.googleapis.com/google.rpc.SomeErrorType".to_owned()),
                    violations: Some(vec![ErrorViolations {
                        description: Some("Description of the violation".to_owned()),
                        field: Some("field-that-violated".to_string()),
                    }]),
                }]),
                message: Some(message.to_owned()),
                status: Some(status_code_uppercase.to_owned()),
            },
        }
    }

    #[test]
    fn test_calculate_retry_sleep_millis() {
        let calc = PushSleepCalculator;
        let seconds = calc.calculate_retry_sleep_millis(0) as f64 / 1000.0;
        let rounded = seconds.round() as u64;
        assert_eq!(rounded, 1);

        let seconds = calc.calculate_retry_sleep_millis(5) as f64 / 1000.0;
        let rounded = seconds.round() as u64;
        assert!((29..=35).contains(&rounded));
    }
}
