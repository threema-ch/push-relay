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
    errors::{InfluxdbError, InitError, SendPushError, ServiceError},
    http_client,
    influxdb::Influxdb,
    push::{
        apns, fcm,
        fcm::{AndroidTtlSeconds, FcmState, HttpOauthTokenObtainer, RequestOauthToken},
        hms::{self, HmsContext, HmsEndpointConfig},
        threema_gateway, ApnsToken, FcmToken, HmsToken, PushToken, ThreemaPayload,
    },
    ThreemaGatewayPrivateKey,
};

static COLLAPSE_KEY_PREFIX: &str = "relay";
static TTL_DEFAULT: u32 = 90;
static PUSH_PATH: &str = "/push";

#[derive(Clone)]
struct AppState<R = HttpOauthTokenObtainer>
where
    R: fcm::RequestOauthToken,
{
    fcm_state: Arc<FcmState<R>>,
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
) -> Result<(), InitError> {
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

    let token_obtainer = HttpOauthTokenObtainer::new(&fcm.service_account_key)
        .await
        .map_err(InitError::Fcm)?;

    let fcm_state = FcmState::new(&fcm, None, token_obtainer)
        .await
        .map_err(InitError::Fcm)?;

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
    let hms_client = http_client::make_client(90).map_err(InitError::Reqwest)?;

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
    let threema_gateway_client = http_client::make_client(90).map_err(InitError::Reqwest)?;

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
        fcm_state: Arc::new(fcm_state),
        apns_client_prod: apns_client_prod.clone(),
        apns_client_sbox: apns_client_sbox.clone(),
        hms_contexts: hms_contexts.clone(),
        hms_config: HmsEndpointConfig::new_shared(),
        threema_gateway_client: threema_gateway_client.clone(),
        threema_gateway_private_key: threema_gateway_private_key.clone(),
        threema_gateway_config: threema_gateway.clone(),
        influxdb: influxdb.clone(),
    };

    let app = get_router::<HttpOauthTokenObtainer>(state);

    let listener = TcpListener::bind(listen_on)
        .await
        .map_err(|source| InitError::Io {
            reason: "Failed to bind to address",
            source,
        })?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| InitError::Io {
        reason: "Failed to serve app",
        source: e,
    })
}

fn get_router<R: RequestOauthToken + 'static>(state: AppState<R>) -> Router {
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

/// Main push handling entry point.
///
/// Handle a request, return a response.
async fn handle_push_request<R: RequestOauthToken>(
    State(state): State<AppState<R>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ServiceError> {
    // Verify content type
    let content_type = headers.get(CONTENT_TYPE).and_then(|h| h.to_str().ok());
    match content_type {
        Some(ct) if ct.starts_with("application/x-www-form-urlencoded") => {}
        Some(ct) => {
            warn!("Bad request, invalid content type: {}", ct);
            return Err(ServiceError::InvalidContentType(ct.to_owned()));
        }
        None => {
            warn!("Bad request, missing content type");
            return Err(ServiceError::MissingContentType);
        }
    }

    let parsed = form_urlencoded::parse(&body).collect::<Vec<_>>();
    trace!("Request params: {:?}", parsed);

    // Validate parameters
    if parsed.is_empty() {
        return Err(ServiceError::MissingParams);
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
                    return Err(ServiceError::MissingParams);
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
                return Err(ServiceError::InvalidParams);
            }
            let public_key_hex = find_or_bad_request!("public_key");
            if public_key_hex.len() != 64 {
                warn!(
                    "Got push request with invalid public key length: {}",
                    public_key_hex.len()
                );
                return Err(ServiceError::InvalidParams);
            }
            let Ok(public_key) = HEXLOWER_PERMISSIVE.decode(public_key_hex.as_bytes()) else {
                warn!(
                    "Got push request with invalid public key: {}",
                    public_key_hex
                );
                return Err(ServiceError::InvalidParams);
            };
            let Ok(public_key) = public_key.try_into() else {
                warn!(
                    "Got push request with invalid public key: {}",
                    public_key_hex
                );
                return Err(ServiceError::InvalidParams);
            };
            PushToken::ThreemaGateway {
                identity,
                public_key,
            }
        }
        other => {
            warn!("Got push request with invalid token type: {}", other);
            return Err(ServiceError::InvalidParams);
        }
    };
    let session_public_key = find_or_bad_request!("session");
    let version_string = find_or_bad_request!("version");
    let version: u16 = match version_string.trim().parse::<u16>() {
        Ok(parsed) => parsed,
        Err(e) => {
            warn!("Got push request with invalid version param: {:?}", e);
            return Err(ServiceError::InvalidParams);
        }
    };
    let affiliation = find!("affiliation").map(Cow::as_ref);
    let ttl_string = find!("ttl").map(|ttl_str| ttl_str.trim().parse());
    let ttl: u32 = match ttl_string {
        // Parsing as u32 succeeded
        Some(Ok(val)) => val,
        // Parsing as u32 failed
        Some(Err(_)) => return Err(ServiceError::InvalidParams),
        // No TTL value was specified
        None => TTL_DEFAULT,
    };
    let collapse_key: Option<String> =
        find!("collapse_key").map(|key| format!("{COLLAPSE_KEY_PREFIX}.{key}"));

    #[allow(clippy::match_wildcard_for_single_variants)]
    let (bundle_id, endpoint, collapse_id) = match push_token {
        PushToken::Apns(_) => {
            let bundle_id = Some(find_or_bad_request!("bundleid"));
            let endpoint_str = find_or_bad_request!("endpoint");
            let endpoint = Some(match endpoint_str.as_ref() {
                "p" => Endpoint::Production,
                "s" => Endpoint::Sandbox,
                _ => return Err(ServiceError::InvalidParams),
            });
            let collapse_id = match collapse_key.as_deref().map(CollapseId::new) {
                Some(Ok(id)) => Some(id),
                Some(Err(_)) => return Err(ServiceError::InvalidParams),
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
            let retry_calc = fcm::get_push_retry_calculator();
            let payload = ThreemaPayload::new(session_public_key, affiliation, version, true);
            let http_payload = fcm::HttpV1Payload::new(
                AndroidTtlSeconds::new(ttl),
                token.as_ref(),
                &payload,
                collapse_key.as_deref(),
            );
            fcm::send_push(state.fcm_state.clone(), retry_calc, http_payload, 0)
                .await
                .map(|_| {})
        }
        PushToken::Apns(ref token) => {
            let client = match endpoint.unwrap() {
                Endpoint::Production => {
                    debug!("Using production endpoint");
                    &state.apns_client_prod
                }
                Endpoint::Sandbox => {
                    debug!("Using sandbox endpoint");
                    &state.apns_client_sbox
                }
            };
            apns::send_push(
                client,
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
            None => Err(SendPushError::RemoteClient(format!(
                "Unknown HMS App ID: {app_id}"
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
                Err(SendPushError::RemoteClient(
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
        Err(e) => Ok(Response::builder()
            .status({
                info!("{e}");
                match e {
                    SendPushError::RemoteServer(_) => StatusCode::BAD_GATEWAY,
                    SendPushError::SendError(_) | SendPushError::RemoteClient(_) => {
                        StatusCode::BAD_REQUEST
                    }
                    SendPushError::Internal(_) | SendPushError::RemoteAuth(_) => {
                        StatusCode::INTERNAL_SERVER_ERROR
                    }
                }
            })
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::from("Push not successful"))
            .unwrap()),
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
    use tower::util::ServiceExt;
    use wiremock::{
        matchers::{body_partial_json, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::{config::FcmConfig, server::tests::fcm::test::get_fcm_test_path};

    use self::fcm::{test::MockAccessTokenObtainer, RequestOauthToken};

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

    fn get_test_max_retries() -> u8 {
        6
    }

    fn get_test_fcm_config() -> FcmConfig {
        FcmConfig {
            service_account_key: b"yolo".into(),
            project_id: "12345678".to_string(),
            max_retries: get_test_max_retries(),
        }
    }

    fn get_mock_fcm_response() -> &'static str {
        "{\"name\":\"mock-response\"}"
    }

    async fn get_test_state(
        fcm_config: &FcmConfig,
        fcm_endpoint: Option<String>,
    ) -> AppState<MockAccessTokenObtainer> {
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

        let access_tokan_obtainer =
            fcm::test::MockAccessTokenObtainer::new(&fcm_config.service_account_key)
                .await
                .expect("MockAccessTokenObtainer");

        let fcm_state = FcmState::new(fcm_config, fcm_endpoint, access_tokan_obtainer)
            .await
            .unwrap();

        AppState {
            fcm_state: Arc::new(fcm_state),
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

    async fn get_test_app(fcm_endpoint: Option<String>) -> (Router, FcmConfig) {
        let fcm_config = get_test_fcm_config();
        let state = get_test_state(&fcm_config, fcm_endpoint).await;
        let router = get_router(state);
        (router, fcm_config)
    }

    /// Handle invalid paths
    #[tokio::test]
    async fn test_invalid_path() {
        let (app, _) = get_test_app(None).await;

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();

        let response = app.oneshot(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Handle invalid methods
    #[tokio::test]
    async fn test_invalid_method() {
        let (app, _) = get_test_app(None).await;

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
        let (app, _) = get_test_app(None).await;

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
        let (app, _) = get_test_app(None).await;

        let req = Request::post(PUSH_PATH).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp).await;
        assert_eq!(&body, "Missing content type");
    }

    /// A request without parameters should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_no_params() {
        let (app, _) = get_test_app(None).await;

        let req = Request::post(PUSH_PATH)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp).await;
        assert_eq!(&body, "Missing parameters");
    }

    /// A request with missing parameters should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_missing_params() {
        let (app, _) = get_test_app(None).await;

        let req = Request::post(PUSH_PATH)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("token=1234".to_string())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp).await;
        assert_eq!(&body, "Missing parameters");
    }

    /// A request with missing parameters should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_missing_params_apns() {
        let (app, _) = get_test_app(None).await;

        let req = Request::post(PUSH_PATH)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("type=apns&token=1234&session=123deadbeef&version=3".to_string())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp).await;
        assert_eq!(&body, "Missing parameters");
    }

    /// A request with bad parameters should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_bad_endpoint() {
        let (app, _) = get_test_app(None).await;

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
        assert_eq!(&body, "Invalid parameters");
    }

    /// A request with missing parameters should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_bad_token_type() {
        let (app, _) = get_test_app(None).await;

        let req = Request::post(PUSH_PATH)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("type=abc&token=aassddff&session=deadbeef&version=1".to_string())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp).await;
        assert_eq!(&body, "Invalid parameters");
    }

    /// A request with invalid TTL parameter should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_invalid_ttl() {
        let (app, _) = get_test_app(None).await;

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
        assert_eq!(&body, "Invalid parameters");
    }

    #[tokio::test]
    #[allow(clippy::useless_format)]
    async fn test_fcm_ok() {
        let to = "aassddff";
        let session = "deadbeef";
        let ttl = 120;
        let version = 3;
        let collapse_key = "another_collapse_key";

        let mock_server = MockServer::start().await;

        let expected_body = serde_json::json!({
            "message": {
                "token": to,
                "data": {
                    "wcs": session,
                    "wcv": version.to_string()
                },
                "android": {
                    "collapse_key": format!("relay.{collapse_key}"),
                    "priority": "HIGH",
                    "ttl": format!("{}s", ttl)
                }
            }
        });

        let (app, fcm_config) = get_test_app(Some(mock_server.uri())).await;

        Mock::given(method("POST"))
            .and(path(get_fcm_test_path(&fcm_config)))
            .and(body_partial_json(expected_body))
            .respond_with(ResponseTemplate::new(200).set_body_string(get_mock_fcm_response()))
            .expect(1)
            .mount(&mock_server)
            .await;

        let req = Request::post(PUSH_PATH)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!(
                "type=fcm&token={to}&session={session}&version={version}&ttl={ttl}&collapse_key={collapse_key}",
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

    #[tokio::test]
    #[allow(clippy::useless_format)]
    async fn test_fcm_invalid_response() {
        let to = "aassddff";
        let session = "deadbeef";
        let version = 1;
        let collapse_key = "some_collapse_key";
        let affiliation_id = "some_affiliation_id";

        let mock_server = MockServer::start().await;

        let expected_body = serde_json::json!({
            "message": {
                "token": to,
                "data": {
                    "wcs": session,
                    "wcv": version.to_string(),
                    "wca": affiliation_id
                },
                "android": {
                    "collapse_key": format!("relay.{collapse_key}"),
                    "priority": "HIGH",
                    "ttl": "90s"
                }
            }
        });

        let (app, fcm_config) = get_test_app(Some(mock_server.uri())).await;

        Mock::given(method("POST"))
            .and(path(get_fcm_test_path(&fcm_config)))
            .and(body_partial_json(expected_body))
            .respond_with(ResponseTemplate::new(200).set_body_string("invalid body of response"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let req = Request::post(PUSH_PATH)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!(
                "type=fcm&token={to}&session={session}&version={version}&collapse_key={collapse_key}&affiliation={affiliation_id}",
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        // Validate response
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "text/plain",
        );
    }

    async fn test_fcm_process_error(
        msg: &str,
        status_code: StatusCode,
        expected_http_count: Option<u64>,
        expected_status_code: StatusCode,
    ) {
        let mock_server = MockServer::start().await;

        let (app, fcm_config) = get_test_app(Some(mock_server.uri())).await;

        let error_body =
            fcm::test::get_fcm_error(status_code, &format!("Description of the error {msg}"), msg);

        Mock::given(method("POST"))
            .and(path(get_fcm_test_path(&fcm_config)))
            .respond_with(ResponseTemplate::new(status_code.as_u16()).set_body_json(error_body))
            .expect(expected_http_count.unwrap_or(1))
            .mount(&mock_server)
            .await;

        let req = Request::post(PUSH_PATH)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("type=fcm&token=aassddff&session=deadbeef&version=1".to_string())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), expected_status_code);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "text/plain",
        );
        let body = get_body(resp).await;
        assert_eq!(&body, "Push not successful");
    }

    #[tokio::test]
    async fn test_fcm_invalid() {
        test_fcm_process_error(
            "INVALID_ARGUMENT",
            StatusCode::BAD_REQUEST,
            None,
            StatusCode::BAD_REQUEST,
        )
        .await;
    }

    #[tokio::test]
    async fn test_fcm_unregistered() {
        test_fcm_process_error(
            "UNREGISTERED",
            StatusCode::NOT_FOUND,
            None,
            StatusCode::BAD_REQUEST,
        )
        .await;
    }

    #[tokio::test]
    async fn test_fcm_sender_id_mismatch() {
        test_fcm_process_error(
            "SENDER_ID_MISMATCH",
            StatusCode::FORBIDDEN,
            None,
            StatusCode::BAD_GATEWAY,
        )
        .await;
    }

    #[tokio::test]
    async fn test_fcm_unavailable() {
        test_fcm_process_error(
            "UNAVAILABLE",
            StatusCode::SERVICE_UNAVAILABLE,
            Some((get_test_max_retries() + 1).into()),
            StatusCode::BAD_GATEWAY,
        )
        .await;
    }

    #[tokio::test]
    async fn test_fcm_internal_server_error() {
        test_fcm_process_error(
            "INTERNAL",
            StatusCode::INTERNAL_SERVER_ERROR,
            Some((get_test_max_retries() + 1).into()),
            StatusCode::BAD_GATEWAY,
        )
        .await;
    }

    #[tokio::test]
    async fn test_fcm_unknown_error() {
        test_fcm_process_error(
            "YourBicycleWasStolen",
            StatusCode::IM_A_TEAPOT,
            None,
            StatusCode::BAD_GATEWAY,
        )
        .await;
    }
}
