use std::borrow::Cow;
use std::convert::Into;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use a2::client::{Client as ApnsClient, Endpoint};
use a2::CollapseId;
use futures::future::{self, Future, FutureResult};
use futures::Stream;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::status::StatusCode;
use http::{Request, Response};
use hyper::server::Server;
use hyper::service::Service;
use hyper::{Body, Chunk, Method};
use tokio_core::reactor::Core;
use url::form_urlencoded;

use crate::config::Config;
use crate::errors::{InfluxdbError, PushRelayError, SendPushError, ServiceError};
use crate::influxdb::Influxdb;
use crate::push::{apns, fcm};
use crate::push::{ApnsToken, FcmToken, PushToken};

static COLLAPSE_KEY_PREFIX: &str = "relay";
static TTL_DEFAULT: u32 = 90;

/// Start the server and run infinitely.
pub fn serve(
    config: Config,
    apns_api_key: &[u8],
    listen_on: SocketAddr,
) -> Result<(), PushRelayError> {
    // TODO: CSRF

    // Create reactor loop
    let mut core = Core::new().expect("Could not start event loop");

    // Destructure config
    let Config {
        fcm,
        apns,
        influxdb,
    } = config;

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

    // Create InfluxDB client
    let influxdb = influxdb.map(|c| {
        Arc::new(
            Influxdb::init(c.connection_string, &c.user, &c.pass, c.db)
                .expect("Failed to create Influxdb instance"),
        )
    });

    // Initialize InfluxDB
    if let Some(ref db) = influxdb {
        fn log_started(core: &mut Core, db: &Influxdb) {
            if let Err(e) = core.run(db.log_started()) {
                match e {
                    InfluxdbError::DatabaseNotFound => {
                        warn!("InfluxDB database does not yet exist. Create it...");
                        match core.run(db.create_db()) {
                            Ok(_) => log_started(core, db),
                            Err(e) => error!("Could not create InfluxDB database: {}", e),
                        }
                    }
                    other => error!("Could not log starting event to InfluxDB: {}", other),
                }
            };
        };
        debug!("Sending stats to InfluxDB");
        log_started(&mut core, db);
    } else {
        debug!("Not using InfluxDB logging");
    };

    // Service function
    let new_service = move || {
        let future: FutureResult<PushHandler, ServiceError> = future::ok(PushHandler {
            fcm_api_key: fcm.api_key.clone(),
            apns_client_prod: apns_client_prod.clone(),
            apns_client_sbox: apns_client_sbox.clone(),
            influxdb: influxdb.clone(),
        });
        future
    };

    // Create server
    let server = Server::bind(&listen_on).serve(new_service);

    // Start server
    core.run(server).map_err(Into::into)
}

/// The server endpoint that accepts incoming push requests.
pub struct PushHandler {
    fcm_api_key: String,
    apns_client_prod: Arc<Mutex<ApnsClient>>,
    apns_client_sbox: Arc<Mutex<ApnsClient>>,
    influxdb: Option<Arc<Influxdb>>,
}

impl Service for PushHandler {
    // Boilerplate for hooking up hyper's server types
    type ReqBody = Body;
    type ResBody = Body;
    type Error = ServiceError;

    // The future representing the eventual response
    type Future = Box<dyn Future<Item = Response<Self::ResBody>, Error = Self::Error> + Send>;

    fn call(&mut self, req: Request<Self::ResBody>) -> Self::Future {
        debug!("{} {}", req.method(), req.uri());

        // Verify path
        if req.uri().path() != "/push" {
            return Box::new(future::ok(
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .unwrap(),
            ));
        }

        // Verify method
        if req.method() != Method::POST {
            return Box::new(future::ok(
                Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Body::empty())
                    .unwrap(),
            ));
        }

        /// Create a "bad request" response.
        macro_rules! bad_request {
            ($text:expr) => {{
                warn!("Returning \"bad request\" response: {}", $text);
                Box::new(future::ok(
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header(CONTENT_TYPE, "text/plain")
                        .header(CONTENT_LENGTH, &*$text.len().to_string())
                        .body(Body::from($text))
                        .unwrap(),
                )) as Box<dyn Future<Item = _, Error = ServiceError> + Send>
            }};
        }

        /// Create an "internal server error" response.
        macro_rules! server_error {
            ($text:expr) => {{
                warn!("Returning \"invalid server error\" response: {}", $text);
                Box::new(future::ok(
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::empty())
                        .unwrap(),
                ))
            }};
        }

        // Verify content type
        {
            let content_type = req
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|h| h.to_str().ok());
            match content_type {
                Some(ct) if ct.starts_with("application/x-www-form-urlencoded") => {}
                Some(ct) => return bad_request!(format!("Invalid content type: {}", ct)),
                None => return bad_request!("Missing content type"),
            }
        } // Waiting for NLL

        // Parse request body
        let body = req.into_body();
        let fcm_api_key_clone = self.fcm_api_key.clone();
        let apns_client_prod_clone = self.apns_client_prod.clone();
        let apns_client_sbox_clone = self.apns_client_sbox.clone();
        let influxdb_clone = self.influxdb.clone();

        let response_future = body
            // Hyper supports streamed requests, so we first need to
            // concatenate chunks until the request body is complete.
            .concat2()
            .map_err(|e| ServiceError::new(e.to_string()))
            // Once the body is complete, process it
            // Allow high cognitive complexity for now. The code should get
            // simpler in the future with async / await.
            .and_then(
                #[allow(clippy::cognitive_complexity)]
                move |body: Chunk| {
                    let parsed = form_urlencoded::parse(&body).collect::<Vec<_>>();

                    // Validate parameters
                    if parsed.is_empty() {
                        return bad_request!("Invalid or missing parameters");
                    }

                    /// Iterate over parameters and find first matching key.
                    /// Return an optional.
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
                                None => return bad_request!("Invalid or missing parameters"),
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
                        "gcm" | "fcm" => {
                            PushToken::Fcm(FcmToken(find_or_bad_request!("token").to_string()))
                        }
                        "apns" => {
                            PushToken::Apns(ApnsToken(find_or_bad_request!("token").to_string()))
                        }
                        other => {
                            warn!("Got push request with invalid token type: {}", other);
                            return bad_request!("Invalid or missing parameters");
                        }
                    };
                    let session_public_key = find_or_bad_request!("session");
                    let version_string = find_or_bad_request!("version");
                    let version: u16 = match version_string.trim().parse::<u16>() {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            warn!("Got push request with invalid version param: {:?}", e);
                            return bad_request!("Invalid or missing parameters");
                        }
                    };
                    let affiliation = find!("affiliation").map(Cow::as_ref);
                    let ttl_string = find!("ttl").map(|ttl_str| ttl_str.trim().parse());
                    let ttl: u32 = match ttl_string {
                        // Parsing as u32 succeeded
                        Some(Ok(val)) => val,
                        // Parsing as u32 failed
                        Some(Err(_)) => return bad_request!("Invalid or missing parameters"),
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
                                _ => return bad_request!("Invalid or missing parameters"),
                            });
                            let collapse_id = match collapse_key.as_deref().map(CollapseId::new) {
                                Some(Ok(id)) => Some(id),
                                Some(Err(_)) => {
                                    return bad_request!("Invalid or missing parameters")
                                }
                                None => None,
                            };
                            (bundle_id, endpoint, collapse_id)
                        }
                        _ => (None, None, None),
                    };

                    // Send push notification
                    info!(
                        "Sending push message to {} for session {} [v{}]",
                        push_token.abbrev(),
                        session_public_key,
                        version
                    );
                    let push_future = match push_token {
                        PushToken::Fcm(ref token) => fcm::send_push(
                            &fcm_api_key_clone,
                            token,
                            version,
                            &session_public_key,
                            affiliation,
                            collapse_key.as_deref(),
                            fcm::Priority::High,
                            ttl,
                        ),
                        PushToken::Apns(ref token) => apns::send_push(
                            &*match endpoint.unwrap() {
                                Endpoint::Production => {
                                    debug!("Using production endpoint");
                                    match apns_client_prod_clone.lock() {
                                        Ok(guard) => guard,
                                        Err(_) => {
                                            return server_error!(
                                                "Could not lock apns_client_prod_clone mutex"
                                            )
                                        }
                                    }
                                }
                                Endpoint::Sandbox => {
                                    debug!("Using sandbox endpoint");
                                    match apns_client_sbox_clone.lock() {
                                        Ok(guard) => guard,
                                        Err(_) => {
                                            return server_error!(
                                                "Could not lock apns_client_sbox_clone mutex"
                                            )
                                        }
                                    }
                                }
                            },
                            token,
                            bundle_id.expect("bundle_id is None"),
                            version,
                            &session_public_key,
                            affiliation,
                            collapse_id,
                            ttl,
                        ),
                    };

                    Box::new(
                        push_future
                            .then(move |push_res| {
                                let influxdb_future = match influxdb_clone {
                                    Some(influxdb) => future::Either::A(influxdb.log_push(
                                        push_token.abbrev(),
                                        version,
                                        push_res.is_ok(),
                                    )),
                                    None => future::Either::B(future::ok(())),
                                };
                                influxdb_future.then(|influxdb_res| {
                                    if let Err(e) = influxdb_res {
                                        warn!("Could not submit stats to InfluxDB: {}", e);
                                    }
                                    push_res
                                })
                            })
                            .and_then(|_| {
                                debug!("Success!");
                                future::ok(
                                    Response::builder()
                                        .status(StatusCode::NO_CONTENT)
                                        .header(CONTENT_TYPE, "text/plain")
                                        .body(Body::empty())
                                        .unwrap(),
                                )
                            })
                            .or_else(|e: SendPushError| {
                                warn!("Error: {}", e);
                                let body = "Push not successful";
                                future::ok(
                                    Response::builder()
                                        .status(match e {
                                            SendPushError::SendError(_) => StatusCode::BAD_GATEWAY,
                                            SendPushError::ProcessingClientError(_) => {
                                                StatusCode::BAD_REQUEST
                                            }
                                            SendPushError::ProcessingRemoteError(_) => {
                                                StatusCode::BAD_GATEWAY
                                            }
                                            SendPushError::Other(_) => {
                                                StatusCode::INTERNAL_SERVER_ERROR
                                            }
                                        })
                                        .header(CONTENT_LENGTH, &*body.len().to_string())
                                        .header(CONTENT_TYPE, "text/plain")
                                        .body(Body::from(body))
                                        .unwrap(),
                                )
                            }),
                    )
                },
            )
            .map_err(|e| ServiceError::new(e.to_string()));

        Box::new(response_future)
    }
}

#[cfg(test)]
mod tests {
    use hyper;
    use mockito;
    use openssl;

    use super::*;

    use hyper::Body;

    use self::mockito::{mock, Matcher};
    use self::openssl::ec::{EcGroup, EcKey};
    use self::openssl::nid::Nid;

    fn get_body(core: &mut Core, body: Body) -> String {
        let bytes = core.run(body.concat2()).unwrap();
        ::std::str::from_utf8(&bytes).unwrap().to_string()
    }

    fn get_apns_test_key() -> Vec<u8> {
        let curve: Nid = Nid::SECP128R1;
        let group = EcGroup::from_curve_name(curve).unwrap();
        let key = EcKey::generate(&group).unwrap();
        key.private_key_to_pem().unwrap()
    }

    fn get_handler() -> (Core, PushHandler) {
        let core = Core::new().unwrap();
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
        let handler = PushHandler {
            fcm_api_key: "aassddff".into(),
            apns_client_prod: Arc::new(Mutex::new(apns_client_prod)),
            apns_client_sbox: Arc::new(Mutex::new(apns_client_sbox)),
            influxdb: None,
        };
        (core, handler)
    }

    /// Handle invalid paths
    #[test]
    fn test_invalid_path() {
        let (mut core, mut handler) = get_handler();

        let req = Request::post("/larifari").body(Body::empty()).unwrap();
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Handle invalid methods
    #[test]
    fn test_invalid_method() {
        let (mut core, mut handler) = get_handler();

        let req = Request::get("/push").body(Body::empty()).unwrap();
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// Handle invalid request content type
    #[test]
    fn test_invalid_contenttype() {
        let (mut core, mut handler) = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::empty())
            .unwrap();
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(&mut core, resp.into_body());
        assert_eq!(&body, "Invalid content type: text/plain");
    }

    /// Handle missing request content type
    #[test]
    fn test_missing_contenttype() {
        let (mut core, mut handler) = get_handler();

        let req = Request::post("/push").body(Body::empty()).unwrap();
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(&mut core, resp.into_body());
        assert_eq!(&body, "Missing content type");
    }

    /// A request without parameters should result in a HTTP 400 response.
    #[test]
    fn test_no_params() {
        let (mut core, mut handler) = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::empty())
            .unwrap();
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(&mut core, resp.into_body());
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request with missing parameters should result in a HTTP 400 response.
    #[test]
    fn test_missing_params() {
        let (mut core, mut handler) = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("token=1234".into())
            .unwrap();
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(&mut core, resp.into_body());
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request with missing parameters should result in a HTTP 400 response.
    #[test]
    fn test_missing_params_apns() {
        let (mut core, mut handler) = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("type=apns&token=1234&session=123deadbeef&version=3".into())
            .unwrap();
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(&mut core, resp.into_body());
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request with bad parameters should result in a HTTP 400 response.
    #[test]
    fn test_bad_endpoint() {
        let (mut core, mut handler) = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(
                "type=apns&token=1234&session=123deadbeef&version=3&bundleid=jklö&endpoint=q"
                    .into(),
            )
            .unwrap();
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(&mut core, resp.into_body());
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request wit missing parameters should result in a HTTP 400 response.
    #[test]
    fn test_bad_token_type() {
        let (mut core, mut handler) = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("type=abc&token=aassddff&session=deadbeef&version=1".into())
            .unwrap();
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(&mut core, resp.into_body());
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request with invalid TTL parameter should result in a HTTP 400 response.
    #[test]
    fn test_invalid_ttl() {
        let (mut core, mut handler) = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("type=fcm&token=aassddff&session=deadbeef&version=1&ttl=9999999999999999".into())
            .unwrap();
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(&mut core, resp.into_body());
        assert_eq!(&body, "Invalid or missing parameters");
    }

    #[test]
    #[allow(clippy::useless_format)]
    fn test_fcm_ok() {
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

        let (mut core, mut handler) = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!("type=fcm&token={}&session={}&version=1", to, session).into())
            .unwrap();
        let resp = core.run(handler.call(req)).unwrap();

        // Ensure that the mock was properly called
        m.assert();

        // Validate response
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "text/plain",
        );
    }

    fn test_fcm_process_error(msg: &str, status_code: StatusCode) {
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

        let (mut core, mut handler) = get_handler();

        let req = Request::post("/push")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("type=fcm&token=aassddff&session=deadbeef&version=1".into())
            .unwrap();
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), status_code);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "text/plain",
        );
        let body = get_body(&mut core, resp.into_body());
        assert_eq!(&body, "Push not successful");
    }

    #[test]
    fn test_fcm_not_registered() {
        test_fcm_process_error("NotRegistered", StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_fcm_missing_registration() {
        test_fcm_process_error("MissingRegistration", StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_fcm_internal_server_error() {
        test_fcm_process_error("InternalServerError", StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_fcm_unknown_error() {
        test_fcm_process_error("YourBicycleWasStolen", StatusCode::INTERNAL_SERVER_ERROR);
    }
}
