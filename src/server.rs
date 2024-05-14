use std::{borrow::Cow, collections::HashMap, convert::Into, net::SocketAddr, sync::Arc};

use a2::{
    client::{Client as ApnsClient, Endpoint},
    CollapseId,
};
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::Response,
    routing::post,
    Router,
};
use data_encoding::HEXLOWER_PERMISSIVE;
use futures::future::{BoxFuture, FutureExt};
use reqwest::{header::CONTENT_TYPE, Client as HttpClient};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;

use crate::{
    config::{Config, ThreemaGatewayConfig},
    errors::{InfluxdbError, PushRelayError, SendPushError, ServiceError},
    http_client,
    influxdb::Influxdb,
    push::{
        apns, fcm,
        fcm::FcmEndpointConfig,
        hms::{self, HmsContext, HmsEndpointConfig},
        threema_gateway, ApnsToken, FcmToken, HmsToken, PushToken,
    },
    ThreemaGatewayPrivateKey,
};

static COLLAPSE_KEY_PREFIX: &str = "relay";
static TTL_DEFAULT: u32 = 90;
static PUSH_PATH: &str = "/push";

#[derive(Clone)]
struct AppState {
    fcm_client: HttpClient,
    fcm_config: Arc<FcmEndpointConfig>,
    apns_client_prod: ApnsClient,
    apns_client_sbox: ApnsClient,
    hms_contexts: Arc<HashMap<String, HmsContext>>,
    hms_config: Arc<HmsEndpointConfig>,
    threema_gateway_client: HttpClient,
    threema_gateway_config: Option<ThreemaGatewayConfig>,
    threema_gateway_private_key: Option<ThreemaGatewayPrivateKey>,
    influxdb: Option<Arc<Influxdb>>,
}

/// Start the server and run infinitely.
pub async fn serve(
    config: Config,
    apns_api_key: &[u8],
    threema_gateway_private_key: Option<ThreemaGatewayPrivateKey>,
    listen_on: SocketAddr,
) -> Result<(), PushRelayError> {
    // Destructure config
    let Config {
        fcm,
        apns,
        hms,
        threema_gateway,
        influxdb,
    } = config;

    // Convert missing hms config to empty HashMap
    let hms = hms.unwrap_or_default();

    // Create FCM HTTP client
    let fcm_client = http_client::make_client(90)?;

    // Create APNs clients
    let apns_client_prod = apns::create_client(
        Endpoint::Production,
        apns_api_key,
        apns.team_id.clone(),
        apns.key_id.clone(),
    )?;
    let apns_client_sbox =
        apns::create_client(Endpoint::Sandbox, apns_api_key, apns.team_id, apns.key_id)?;

    // Create a shared HMS HTTP client
    let hms_client = http_client::make_client(90)?;

    // Create a HMS context for every config entry
    let hms_contexts = Arc::new(
        hms.iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    HmsContext::new(hms_client.clone(), v.clone()),
                )
            })
            .collect::<HashMap<String, HmsContext>>(),
    );

    // Create Threema Gateway HTTP client
    let threema_gateway_client = http_client::make_client(90)?;

    // Create InfluxDB client
    let influxdb = influxdb.map(|c| {
        Arc::new(
            Influxdb::new(c.connection_string, &c.user, &c.pass, c.db)
                .expect("Failed to create Influxdb instance"),
        )
    });

    // Initialize InfluxDB
    if let Some(ref db) = influxdb {
        fn log_started(db: &Influxdb) -> BoxFuture<'_, ()> {
            async move {
                if let Err(e) = db.log_started().await {
                    match e {
                        InfluxdbError::DatabaseNotFound => {
                            warn!("InfluxDB database does not yet exist. Create it...");
                            match db.create_db().await {
                                Ok(_) => log_started(db).await,
                                Err(e) => error!("Could not create InfluxDB database: {}", e),
                            }
                        }
                        other => error!("Could not log starting event to InfluxDB: {}", other),
                    }
                };
            }
            .boxed()
        }
        debug!("Sending stats to InfluxDB");
        log_started(db).await;
    } else {
        debug!("Not using InfluxDB logging");
    };

    let state = AppState {
        fcm_client: fcm_client.clone(),
        fcm_config: FcmEndpointConfig::new_shared(fcm, fcm::FCM_ENDPOINT),
        apns_client_prod: apns_client_prod.clone(),
        apns_client_sbox: apns_client_sbox.clone(),
        hms_contexts: hms_contexts.clone(),
        hms_config: HmsEndpointConfig::new_shared(),
        threema_gateway_client: threema_gateway_client.clone(),
        threema_gateway_private_key: threema_gateway_private_key.clone(),
        threema_gateway_config: threema_gateway.clone(),
        influxdb: influxdb.clone(),
    };

    let app = get_router(state);

    let listener = TcpListener::bind(listen_on)
        .await
        .map_err(|e| PushRelayError::IoError {
            reason: "Failed to bind to address",
            source: e,
        })?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| PushRelayError::IoError {
        reason: "Failed to serve app",
        source: e,
    })
}

fn get_router(state: AppState) -> Router {
    axum::Router::new()
        .route(PUSH_PATH, post(handle_push_request))
        .layer(
            ServiceBuilder::new().layer(
                TraceLayer::new_for_http()
                    .make_span_with(|req: &Request<_>| {
                        let maybe_port = req
                            .extensions()
                            .get::<axum::extract::ConnectInfo<SocketAddr>>()
                            .map(|ci| ci.0.port());
                        const SPAN_NAME: &str = "handle_push";
                        if let Some(port) = maybe_port {
                            info_span!(SPAN_NAME, "type" = tracing::field::Empty, "port" = port)
                        } else {
                            info_span!(SPAN_NAME, "type" = tracing::field::Empty)
                        }
                    })
                    .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
            ),
        )
        .with_state(state)
}

mod responses {
    use super::*;

    /// Return a generic "400 bad request" response.
    pub fn bad_request(body: impl Into<Body>) -> axum::response::Response<Body> {
        Response::builder()
            .status(reqwest::StatusCode::BAD_REQUEST)
            .header(CONTENT_TYPE, "text/plain")
            .body(body.into())
            .unwrap()
    }
}

/// Main push handling entry point.
///
/// Handle a request, return a response.
async fn handle_push_request(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<axum::response::Response, ServiceError> {
    // Verify content type
    let content_type = headers.get(CONTENT_TYPE).and_then(|h| h.to_str().ok());
    match content_type {
        Some(ct) if ct.starts_with("application/x-www-form-urlencoded") => {}
        Some(ct) => {
            warn!("Bad request, invalid content type: {}", ct);
            return Ok(responses::bad_request(format!(
                "Invalid content type: {}",
                ct
            )));
        }
        None => {
            warn!("Bad request, missing content type");
            return Ok(responses::bad_request("Missing content type"));
        }
    }

    let parsed = form_urlencoded::parse(&body).collect::<Vec<_>>();
    trace!("Request params: {:?}", parsed);

    // Validate parameters
    if parsed.is_empty() {
        return Ok(responses::bad_request("Invalid or missing parameters"));
    }

    /// Iterate over parameters and find first matching key.
    /// Return an option.
    macro_rules! find {
        ($name:expr) => {
            parsed
                .iter()
                .find(|&&(ref k, _)| k == $name)
                .map(|&(_, ref v)| v)
        };
    }

    /// Iterate over parameters and find first matching key.
    /// If the key is not found, then return a HTTP 400 response.
    macro_rules! find_or_bad_request {
        ($name:expr) => {
            match find!($name) {
                Some(v) => v,
                None => {
                    warn!("Missing request parameter: {}", $name);
                    return Ok(responses::bad_request("Invalid or missing parameters"));
                }
            }
        };
    }

    /// Iterate over parameters and find first matching key.
    /// If the key is not found, return a default.
    macro_rules! find_or_default {
        ($name:expr, $default:expr) => {
            match find!($name) {
                Some(v) => v,
                None => $default,
            }
        };
    }

    let push_type = find_or_default!("type", "fcm");
    {
        let span = tracing::Span::current();
        span.record("type", push_type);
    }

    // Get parameters
    let push_token = match push_type {
        "gcm" | "fcm" => PushToken::Fcm(FcmToken(find_or_bad_request!("token").to_string())),
        "apns" => PushToken::Apns(ApnsToken(find_or_bad_request!("token").to_string())),
        "hms" => PushToken::Hms {
            token: HmsToken(find_or_bad_request!("token").to_string()),
            app_id: find_or_bad_request!("appid").to_string(),
        },
        "threema-gateway" => {
            let identity = find_or_bad_request!("identity").to_string();
            if identity.len() != 8 || identity.starts_with('*') {
                warn!("Got push request with invalid identity: {}", identity);
                return Ok(responses::bad_request("Invalid or missing parameters"));
            }
            let public_key_hex = find_or_bad_request!("public_key");
            if public_key_hex.len() != 64 {
                warn!(
                    "Got push request with invalid public key length: {}",
                    public_key_hex.len()
                );
                return Ok(responses::bad_request("Invalid or missing parameters"));
            }
            let Ok(public_key) = HEXLOWER_PERMISSIVE.decode(public_key_hex.as_bytes()) else {
                warn!(
                    "Got push request with invalid public key: {}",
                    public_key_hex
                );
                return Ok(responses::bad_request("Invalid or missing parameters"));
            };
            let Ok(public_key) = public_key.try_into() else {
                warn!(
                    "Got push request with invalid public key: {}",
                    public_key_hex
                );
                return Ok(responses::bad_request("Invalid or missing parameters"));
            };
            PushToken::ThreemaGateway {
                identity,
                public_key,
            }
        }
        other => {
            warn!("Got push request with invalid token type: {}", other);
            return Ok(responses::bad_request("Invalid or missing parameters"));
        }
    };
    let session_public_key = find_or_bad_request!("session");
    let version_string = find_or_bad_request!("version");
    let version: u16 = match version_string.trim().parse::<u16>() {
        Ok(parsed) => parsed,
        Err(e) => {
            warn!("Got push request with invalid version param: {:?}", e);
            return Ok(responses::bad_request("Invalid or missing parameters"));
        }
    };
    let affiliation = find!("affiliation").map(Cow::as_ref);
    let ttl_string = find!("ttl").map(|ttl_str| ttl_str.trim().parse());
    let ttl: u32 = match ttl_string {
        // Parsing as u32 succeeded
        Some(Ok(val)) => val,
        // Parsing as u32 failed
        Some(Err(_)) => return Ok(responses::bad_request("Invalid or missing parameters")),
        // No TTL value was specified
        None => TTL_DEFAULT,
    };
    let collapse_key: Option<String> =
        find!("collapse_key").map(|key| format!("{}.{}", COLLAPSE_KEY_PREFIX, key));
    #[allow(clippy::match_wildcard_for_single_variants)]
    let (bundle_id, endpoint, collapse_id) = match push_token {
        PushToken::Apns(_) => {
            let bundle_id = Some(find_or_bad_request!("bundleid"));
            let endpoint_str = find_or_bad_request!("endpoint");
            let endpoint = Some(match endpoint_str.as_ref() {
                "p" => Endpoint::Production,
                "s" => Endpoint::Sandbox,
                _ => return Ok(responses::bad_request("Invalid or missing parameters")),
            });
            let collapse_id = match collapse_key.as_deref().map(CollapseId::new) {
                Some(Ok(id)) => Some(id),
                Some(Err(_)) => return Ok(responses::bad_request("Invalid or missing parameters")),
                None => None,
            };
            (bundle_id, endpoint, collapse_id)
        }
        _ => (None, None, None),
    };

    // Send push notification
    let variant = match bundle_id {
        Some(bid) if bid.ends_with(".voip") => "/s",
        Some(_bid) => "/n",
        None => "",
    };
    info!(
        "Sending push message to {}{} for session {} [v{}]",
        push_token.abbrev(),
        variant,
        session_public_key,
        version
    );
    let push_result = match push_token {
        PushToken::Fcm(ref token) => {
            fcm::send_push(
                &state.fcm_client,
                &state.fcm_config,
                token,
                version,
                session_public_key,
                affiliation,
                collapse_key.as_deref(),
                ttl,
            )
            .await
        }
        PushToken::Apns(ref token) => {
            let client = match endpoint.unwrap() {
                Endpoint::Production => {
                    debug!("Using production endpoint");
                    state.apns_client_prod
                }
                Endpoint::Sandbox => {
                    debug!("Using sandbox endpoint");
                    state.apns_client_sbox
                }
            };
            apns::send_push(
                &client,
                token,
                bundle_id.expect("bundle_id is None"),
                version,
                session_public_key,
                affiliation,
                collapse_id,
                ttl,
            )
            .await
        }
        PushToken::Hms {
            ref token,
            ref app_id,
        } => match state.hms_contexts.get(app_id) {
            // We found a context for this App ID
            Some(context) => {
                hms::send_push(
                    context,
                    &state.hms_config,
                    token,
                    version,
                    session_public_key,
                    affiliation,
                    ttl,
                )
                .await
            }
            // No config found for this App ID
            None => Err(SendPushError::ProcessingClientError(format!(
                "Unknown HMS App ID: {}",
                app_id
            ))),
        },
        PushToken::ThreemaGateway {
            ref identity,
            ref public_key,
        } => {
            if let (Some(threema_gateway_config), Some(threema_gateway_private_key)) = (
                state.threema_gateway_config,
                state.threema_gateway_private_key,
            ) {
                threema_gateway::send_push(
                    &state.threema_gateway_client,
                    &threema_gateway_config.base_url,
                    &threema_gateway_config.secret,
                    &threema_gateway_config.identity,
                    threema_gateway_private_key,
                    identity,
                    *public_key,
                    version,
                    session_public_key,
                    affiliation,
                )
                .await
            } else {
                // No config found for Threema Gateway
                Err(SendPushError::ProcessingClientError(
                    "Cannot send Threema Gateway Push, not configured".into(),
                ))
            }
        }
    };

    // Log to InfluxDB
    if let Some(influxdb) = state.influxdb {
        let log_result = influxdb
            .log_push(push_token.abbrev(), version, push_result.is_ok())
            .await;
        if let Err(e) = log_result {
            warn!("Could not submit stats to InfluxDB: {}", e);
        }
    }

    // Handle result
    match push_result {
        Ok(()) => {
            debug!("Success!");
            Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::empty())
                .unwrap())
        }
        Err(e) => {
            warn!("Error: {}", e);
            Ok(Response::builder()
                .status(match e {
                    SendPushError::SendError(_) => StatusCode::BAD_GATEWAY,
                    SendPushError::ProcessingClientError(_) => StatusCode::BAD_REQUEST,
                    SendPushError::ProcessingRemoteError(_) => StatusCode::BAD_GATEWAY,
                    SendPushError::AuthError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                    SendPushError::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
                })
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from("Push not successful"))
                .unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{Request, Response};
    use futures::StreamExt;
    use openssl::{
        ec::{EcGroup, EcKey},
        nid::Nid,
    };
    use tower::ServiceExt;
    use wiremock::{
        matchers::{body_partial_json, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;

    async fn get_body(res: Response<Body>) -> String {
        let mut full_body = Vec::new();
        let mut body = res.into_body().into_data_stream();
        while let Some(chunk) = body.next().await {
            full_body.extend_from_slice(&chunk.unwrap());
        }
        ::std::str::from_utf8(&full_body).unwrap().to_string()
    }

    fn get_apns_test_key() -> Vec<u8> {
        let curve: Nid = Nid::SECP128R1;
        let group = EcGroup::from_curve_name(curve).unwrap();
        let key = EcKey::generate(&group).unwrap();
        key.private_key_to_pem().unwrap()
    }

    fn get_test_state(fcm_endpoint: Option<String>) -> AppState {
        let fcm_client = http_client::make_client(10).expect("fcm_client");
        let api_key = get_apns_test_key();
        let apns_client_prod = apns::create_client(
            Endpoint::Production,
            api_key.as_slice(),
            "team_id",
            "key_id",
        )
        .unwrap();
        let apns_client_sbox =
            apns::create_client(Endpoint::Sandbox, api_key.as_slice(), "team_id", "key_id")
                .unwrap();
        let threema_gateway_client = http_client::make_client(10).expect("threema_gateway_client");
        AppState {
            fcm_client,
            fcm_config: FcmEndpointConfig::stub_with(fcm_endpoint),
            apns_client_prod,
            apns_client_sbox,
            hms_contexts: Arc::new(HashMap::new()),
            hms_config: HmsEndpointConfig::stub_with(None),
            threema_gateway_client,
            threema_gateway_config: None,
            threema_gateway_private_key: None,
            influxdb: None,
        }
    }

    fn get_test_app_with(fcm_endpoint: String) -> Router {
        get_router(get_test_state(Some(fcm_endpoint)))
    }

    fn get_test_app() -> Router {
        get_router(get_test_state(None))
    }

    /// Handle invalid paths
    #[tokio::test]
    async fn test_invalid_path() {
        let app = get_test_app();

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();

        let response = app.oneshot(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Handle invalid methods
    #[tokio::test]
    async fn test_invalid_method() {
        let app = get_test_app();

        let req = Request::builder()
            .method("GET")
            .uri(PUSH_PATH)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// Handle invalid request content type
    #[tokio::test]
    async fn test_invalid_contenttype() {
        let app = get_test_app();

        let req = Request::post(PUSH_PATH)
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp).await;
        assert_eq!(&body, "Invalid content type: text/plain");
    }

    /// Handle missing request content type
    #[tokio::test]
    async fn test_missing_contenttype() {
        let app = get_test_app();

        let req = Request::post(PUSH_PATH).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp).await;
        assert_eq!(&body, "Missing content type");
    }

    /// A request without parameters should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_no_params() {
        let app = get_test_app();

        let req = Request::post(PUSH_PATH)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp).await;
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request with missing parameters should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_missing_params() {
        let app = get_test_app();

        let req = Request::post(PUSH_PATH)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("token=1234".to_string())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp).await;
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request with missing parameters should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_missing_params_apns() {
        let app = get_test_app();

        let req = Request::post(PUSH_PATH)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("type=apns&token=1234&session=123deadbeef&version=3".to_string())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp).await;
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request with bad parameters should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_bad_endpoint() {
        let app = get_test_app();

        let req = Request::post(PUSH_PATH)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(
                "type=apns&token=1234&session=123deadbeef&version=3&bundleid=jklö&endpoint=q"
                    .to_string(),
            )
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp).await;
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request wit missing parameters should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_bad_token_type() {
        let app = get_test_app();

        let req = Request::post(PUSH_PATH)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("type=abc&token=aassddff&session=deadbeef&version=1".to_string())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp).await;
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request with invalid TTL parameter should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_invalid_ttl() {
        let app = get_test_app();

        let req = Request::post(PUSH_PATH)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(
                "type=fcm&token=aassddff&session=deadbeef&version=1&ttl=9999999999999999"
                    .to_string(),
            )
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp).await;
        assert_eq!(&body, "Invalid or missing parameters");
    }

    #[tokio::test]
    #[allow(clippy::useless_format)]
    async fn test_fcm_ok() {
        let to = "aassddff";
        let session = "deadbeef";

        let mock_server = MockServer::start().await;

        let expected_body = serde_json::json!({
            "to": to,
            "priority": "high",
            "time_to_live": 90,
            "data": {
                "wcs": session,
                "wca": null,
                "wcv": 1
            }
        });

        Mock::given(method("POST"))
            .and(path(fcm::FCM_PATH))
            .and(body_partial_json(expected_body))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{
                "multicast_id": 1,
                "success": 1,
                "failure": 0,
                "canonical_ids": 0,
                "results": null
            }"#,
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        let app = get_test_app_with(mock_server.uri());

        let req = Request::post(PUSH_PATH)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!(
                "type=fcm&token={}&session={}&version=1",
                to, session
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        // Validate response
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "text/plain",
        );
    }

    async fn test_fcm_process_error(msg: &str, status_code: StatusCode) {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(fcm::FCM_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"{{
                    "multicast_id": 1,
                    "success": 0,
                    "failure": 1,
                    "canonical_ids": 0,
                    "results": [{{"error": "{}"}}]
                }}"#,
                msg,
            )))
            .expect(1)
            .mount(&mock_server)
            .await;

        let app = get_test_app_with(mock_server.uri());

        let req = Request::post(PUSH_PATH)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("type=fcm&token=aassddff&session=deadbeef&version=1".to_string())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), status_code);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "text/plain",
        );
        let body = get_body(resp).await;
        assert_eq!(&body, "Push not successful");
    }

    #[tokio::test]
    async fn test_fcm_not_registered() {
        test_fcm_process_error("NotRegistered", StatusCode::BAD_REQUEST).await;
    }

    #[tokio::test]
    async fn test_fcm_missing_registration() {
        test_fcm_process_error("MissingRegistration", StatusCode::BAD_REQUEST).await;
    }

    #[tokio::test]
    async fn test_fcm_internal_server_error() {
        test_fcm_process_error("InternalServerError", StatusCode::BAD_GATEWAY).await;
    }

    #[tokio::test]
    async fn test_fcm_unknown_error() {
        test_fcm_process_error("YourBicycleWasStolen", StatusCode::INTERNAL_SERVER_ERROR).await;
    }
}
