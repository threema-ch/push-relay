use std::{
    borrow::Cow,
    collections::HashMap,
    convert::Into,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use a2::client::{Client as ApnsClient, Endpoint};
use a2::CollapseId;
use data_encoding::HEXLOWER_PERMISSIVE;
use futures::future::{BoxFuture, FutureExt};
use http::status::StatusCode;
use hyper::{
    body::{self, Body, Bytes},
    header::CONTENT_TYPE,
    server::{conn::AddrStream, Server},
    service::{make_service_fn, Service},
    Method, Request, Response,
};
use tokio::sync::Mutex;

use crate::{
    config::{Config, ThreemaGatewayConfig},
    errors::{InfluxdbError, PushRelayError, SendPushError, ServiceError},
    http_client::{self, HttpClient},
    influxdb::Influxdb,
    push::{
        apns, fcm,
        hms::{self, HmsContext},
        threema_gateway, ApnsToken, FcmToken, HmsToken, PushToken,
    },
    ThreemaGatewayPrivateKey,
};

static COLLAPSE_KEY_PREFIX: &str = "relay";
static TTL_DEFAULT: u32 = 90;

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
    let fcm_client = http_client::make_client(90);

    // Create APNs clients
    let apns_client_prod = Arc::new(Mutex::new(apns::create_client(
        Endpoint::Production,
        apns_api_key,
        apns.team_id.clone(),
        apns.key_id.clone(),
    )?));
    let apns_client_sbox = Arc::new(Mutex::new(apns::create_client(
        Endpoint::Sandbox,
        apns_api_key,
        apns.team_id,
        apns.key_id,
    )?));

    // Create a shared HMS HTTP client
    let hms_client = http_client::make_client(90);

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
    let threema_gateway_client = http_client::make_client(90);

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

    // Create server
    let make_svc = make_service_fn(|_conn: &AddrStream| {
        let service = PushHandler {
            fcm_client: fcm_client.clone(),
            fcm_api_key: fcm.api_key.clone(),
            apns_client_prod: apns_client_prod.clone(),
            apns_client_sbox: apns_client_sbox.clone(),
            hms_contexts: hms_contexts.clone(),
            threema_gateway_client: threema_gateway_client.clone(),
            threema_gateway_private_key: threema_gateway_private_key.clone(),
            threema_gateway_config: threema_gateway.clone(),
            influxdb: influxdb.clone(),
        };
        async move { Ok::<_, ServiceError>(service) }
    });
    let server = Server::bind(&listen_on).serve(make_svc);

    // Run until completion
    server.await?;
    Ok(())
}

/// The server endpoint that accepts incoming push requests.
pub struct PushHandler {
    fcm_client: HttpClient,
    fcm_api_key: String,
    apns_client_prod: Arc<Mutex<ApnsClient>>,
    apns_client_sbox: Arc<Mutex<ApnsClient>>,
    hms_contexts: Arc<HashMap<String, HmsContext>>,
    threema_gateway_client: HttpClient,
    threema_gateway_config: Option<ThreemaGatewayConfig>,
    threema_gateway_private_key: Option<ThreemaGatewayPrivateKey>,
    influxdb: Option<Arc<Influxdb>>,
}

mod responses {
    use super::*;

    /// Return a generic "400 bad request" response.
    pub fn bad_request(body: impl Into<Body>) -> Response<Body> {
        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(CONTENT_TYPE, "text/plain")
            .body(body.into())
            .unwrap()
    }

    /// Return a generic "404 not found" response.
    pub fn not_found() -> Response<Body> {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::from("Not found"))
            .unwrap()
    }

    /// Return a generic "405 method not allowed" response.
    pub fn method_not_allowed() -> Response<Body> {
        Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::from("Method not allowed"))
            .unwrap()
    }

    /// Return a generic "500 internal server error" response.
    pub fn internal_server_error() -> Response<Body> {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::from("Internal server error"))
            .unwrap()
    }
}

/// Main push handling entry point.
///
/// Handle a request, return a response.
async fn handle_push_request(
    req: Request<Body>,
    fcm_client: HttpClient,
    fcm_api_key: String,
    apns_client_prod: Arc<Mutex<ApnsClient>>,
    apns_client_sbox: Arc<Mutex<ApnsClient>>,
    hms_contexts: Arc<HashMap<String, HmsContext>>,
    threema_gateway_client: HttpClient,
    threema_gateway_config: Option<ThreemaGatewayConfig>,
    threema_gateway_private_key: Option<ThreemaGatewayPrivateKey>,
    influxdb: Option<Arc<Influxdb>>,
) -> Result<Response<Body>, ServiceError> {
    debug!("{} {}", req.method(), req.uri());

    // Verify path
    if req.uri().path() != "/push" {
        return Ok(responses::not_found());
    }

    // Verify method
    if req.method() != Method::POST {
        return Ok(responses::method_not_allowed());
    }

    // Verify content type
    let content_type = req
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|h| h.to_str().ok());
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

    // Parse request body
    let body: Bytes = match body::to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Could not convert body to bytes: {}", e);
            return Ok(responses::internal_server_error());
        }
    };
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

    // Get parameters
    let push_token = match find_or_default!("type", "fcm") {
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
                &fcm_client,
                &fcm_api_key,
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
                    apns_client_prod.lock().await
                }
                Endpoint::Sandbox => {
                    debug!("Using sandbox endpoint");
                    apns_client_sbox.lock().await
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
        } => match hms_contexts.get(app_id) {
            // We found a context for this App ID
            Some(context) => {
                hms::send_push(
                    context,
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
            if let (Some(threema_gateway_config), Some(threema_gateway_private_key)) =
                (threema_gateway_config, threema_gateway_private_key)
            {
                threema_gateway::send_push(
                    &threema_gateway_client,
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
    if let Some(influxdb) = influxdb {
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

impl Service<Request<Body>> for PushHandler {
    type Response = Response<Body>;
    type Error = ServiceError;
    #[allow(clippy::type_complexity)]
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    /// Main service entry point.
    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // Delegate to async fn
        let fcm_client = self.fcm_client.clone();
        let fcm_api_key = self.fcm_api_key.clone();
        let apns_client_prod = self.apns_client_prod.clone();
        let apns_client_sbox = self.apns_client_sbox.clone();
        let hms_contexts = self.hms_contexts.clone();
        let threema_gateway_client = self.threema_gateway_client.clone();
        let threema_gateway_config = self.threema_gateway_config.clone();
        let threema_gateway_private_key = self.threema_gateway_private_key.clone();
        let influxdb = self.influxdb.clone();
        let fut = async move {
            let res = handle_push_request(
                req,
                fcm_client,
                fcm_api_key,
                apns_client_prod,
                apns_client_sbox,
                hms_contexts,
                threema_gateway_client,
                threema_gateway_config,
                threema_gateway_private_key,
                influxdb,
            )
            .await;
            match res {
                Ok(ref resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        debug!("Returning HTTP {}", status);
                    } else {
                        info!("Returning HTTP {}", status);
                    }
                }
                Err(ref e) => warn!("Request processing failed: {}", e),
            }
            res
        };
        Box::pin(fut)
    }
}

#[cfg(test)]
mod tests {
    use hyper::Body;
    use mockito::{mock, Matcher};
    use openssl::{
        ec::{EcGroup, EcKey},
        nid::Nid,
    };

    use super::*;

    async fn get_body(body: Body) -> String {
        let bytes = body::to_bytes(body).await.unwrap();
        ::std::str::from_utf8(&bytes).unwrap().to_string()
    }

    fn get_apns_test_key() -> Vec<u8> {
        let curve: Nid = Nid::SECP128R1;
        let group = EcGroup::from_curve_name(curve).unwrap();
        let key = EcKey::generate(&group).unwrap();
        key.private_key_to_pem().unwrap()
    }

    fn get_handler() -> PushHandler {
        let fcm_client = http_client::make_client(10);
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
        let threema_gateway_client = http_client::make_client(10);
        PushHandler {
            fcm_client,
            fcm_api_key: "aassddff".into(),
            apns_client_prod: Arc::new(Mutex::new(apns_client_prod)),
            apns_client_sbox: Arc::new(Mutex::new(apns_client_sbox)),
            hms_contexts: Arc::new(HashMap::new()),
            threema_gateway_client,
            threema_gateway_config: None,
            threema_gateway_private_key: None,
            influxdb: None,
        }
    }

    /// Handle invalid paths
    #[tokio::test]
    async fn test_invalid_path() {
        let mut handler = get_handler();

        let req = Request::post("/larifari").body(Body::empty()).unwrap();
        let resp = handler.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Handle invalid methods
    #[tokio::test]
    async fn test_invalid_method() {
        let mut handler = get_handler();

        let req = Request::get("/push").body(Body::empty()).unwrap();
        let resp = handler.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// Handle invalid request content type
    #[tokio::test]
    async fn test_invalid_contenttype() {
        let mut handler = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::empty())
            .unwrap();
        let resp = handler.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp.into_body()).await;
        assert_eq!(&body, "Invalid content type: text/plain");
    }

    /// Handle missing request content type
    #[tokio::test]
    async fn test_missing_contenttype() {
        let mut handler = get_handler();

        let req = Request::post("/push").body(Body::empty()).unwrap();
        let resp = handler.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp.into_body()).await;
        assert_eq!(&body, "Missing content type");
    }

    /// A request without parameters should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_no_params() {
        let mut handler = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::empty())
            .unwrap();
        let resp = handler.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp.into_body()).await;
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request with missing parameters should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_missing_params() {
        let mut handler = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("token=1234".into())
            .unwrap();
        let resp = handler.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp.into_body()).await;
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request with missing parameters should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_missing_params_apns() {
        let mut handler = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("type=apns&token=1234&session=123deadbeef&version=3".into())
            .unwrap();
        let resp = handler.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp.into_body()).await;
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request with bad parameters should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_bad_endpoint() {
        let mut handler = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(
                "type=apns&token=1234&session=123deadbeef&version=3&bundleid=jklö&endpoint=q"
                    .into(),
            )
            .unwrap();
        let resp = handler.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp.into_body()).await;
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request wit missing parameters should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_bad_token_type() {
        let mut handler = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("type=abc&token=aassddff&session=deadbeef&version=1".into())
            .unwrap();
        let resp = handler.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp.into_body()).await;
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request with invalid TTL parameter should result in a HTTP 400 response.
    #[tokio::test]
    async fn test_invalid_ttl() {
        let mut handler = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("type=fcm&token=aassddff&session=deadbeef&version=1&ttl=9999999999999999".into())
            .unwrap();
        let resp = handler.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(resp.into_body()).await;
        assert_eq!(&body, "Invalid or missing parameters");
    }

    #[tokio::test]
    #[allow(clippy::useless_format)]
    async fn test_fcm_ok() {
        let to = "aassddff";
        let session = "deadbeef";

        let m = mock("POST", "/fcm/send")
            .match_body(Matcher::AllOf(vec![
                Matcher::Regex(format!("\"to\":\"{}\"", to)),
                Matcher::Regex(format!("\"priority\":\"high\"")),
                Matcher::Regex(format!("\"time_to_live\":90")),
                Matcher::Regex(format!("\"wcs\":\"{}\"", session)),
                Matcher::Regex(format!("\"wca\":null")),
                Matcher::Regex(format!("\"wcv\":1")),
            ]))
            .with_status(200)
            .with_body(
                r#"{
                    "multicast_id": 1,
                    "success": 1,
                    "failure": 0,
                    "canonical_ids": 0,
                    "results": null
                }"#,
            )
            .create();

        let mut handler = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!("type=fcm&token={}&session={}&version=1", to, session).into())
            .unwrap();
        let resp = handler.call(req).await.unwrap();

        // Ensure that the mock was properly called
        m.assert();

        // Validate response
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "text/plain",
        );
    }

    async fn test_fcm_process_error(msg: &str, status_code: StatusCode) {
        let _m = mock("POST", "/fcm/send")
            .with_status(200)
            .with_body(format!(
                r#"{{
                    "multicast_id": 1,
                    "success": 0,
                    "failure": 1,
                    "canonical_ids": 0,
                    "results": [{{"error": "{}"}}]
                }}"#,
                msg,
            ))
            .create();

        let mut handler = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("type=fcm&token=aassddff&session=deadbeef&version=1".into())
            .unwrap();
        let resp = handler.call(req).await.unwrap();

        assert_eq!(resp.status(), status_code);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "text/plain",
        );
        let body = get_body(resp.into_body()).await;
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
