use std::convert::Into;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use a2::client::{Client as ApnsClient, Endpoint};
use futures::Stream;
use futures::future::{self, Future, FutureResult};
use http::{Request, Response};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::status::StatusCode;
use hyper::{Body, Chunk, Method};
use hyper::server::Server;
use hyper::service::Service;
use tokio_core::reactor::Core;
use url::form_urlencoded;

use errors::{PushRelayError, SendPushError, ServiceError};
use push::{ApnsToken, GcmToken, PushToken};
use push::{apns, gcm};


/// Start the server and run infinitely.
pub fn serve(
    gcm_api_key: &str,
    apns_api_key: Vec<u8>,
    apns_team_id: &str,
    apns_key_id: &str,
    listen_on: SocketAddr,
) -> Result<(), PushRelayError> {
    // TODO: CSRF

    // Create reactor loop
    let mut core = Core::new().expect("Could not start event loop");

    // Create APNs clients
    let apns_client_prod = Arc::new(Mutex::new(apns::create_client(
        Endpoint::Production,
        apns_api_key.as_slice(),
        apns_team_id,
        apns_key_id,
    )?));
    let apns_client_sbox = Arc::new(Mutex::new(apns::create_client(
        Endpoint::Sandbox,
        apns_api_key.as_slice(),
        apns_team_id,
        apns_key_id,
    )?));

    // Service function
    let gcm_api_key_owned = gcm_api_key.to_string();
    let new_service = move || {
        let future: FutureResult<PushHandler, ServiceError> = future::ok(
            PushHandler {
                gcm_api_key: gcm_api_key_owned.clone(),
                apns_client_prod: apns_client_prod.clone(),
                apns_client_sbox: apns_client_sbox.clone(),
            }
        );
        future
    };

    // Create server
    let server = Server::bind(&listen_on).serve(new_service);

    // Start server
    core.run(server).map_err(Into::into)
}


/// The server endpoint that accepts incoming push requests.
pub struct PushHandler {
    gcm_api_key: String,
    apns_client_prod: Arc<Mutex<ApnsClient>>,
    apns_client_sbox: Arc<Mutex<ApnsClient>>,
}

impl Service for PushHandler {
    // Boilerplate for hooking up hyper's server types
    type ReqBody = Body;
    type ResBody = Body;
    type Error = ServiceError;

    // The future representing the eventual response
    type Future = Box<Future<Item=Response<Self::ResBody>, Error=Self::Error> + Send>;

    fn call(&mut self, req: Request<Self::ResBody>) -> Self::Future {
        info!("{} {}", req.method(), req.uri());

        // Verify path
        if req.uri().path() != "/push" {
            return Box::new(future::ok(
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .unwrap()
            ));
        }

        // Verify method
        if req.method() != &Method::POST {
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
                        .unwrap()
                )) as Box<Future<Item=_, Error=ServiceError> + Send>
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
                        .unwrap()
                ))
            }};
        }

        // Verify content type
        {
            let content_type = req.headers().get(CONTENT_TYPE).and_then(|h| h.to_str().ok());
            if content_type != Some("application/x-www-form-urlencoded") {
                return bad_request!("Invalid content type");
            }
        } // Waiting for NLL

        // Parse request body
        let body = req.into_body();
        let gcm_api_key_clone = self.gcm_api_key.clone();
        let apns_client_prod_clone = self.apns_client_prod.clone();
        let apns_client_sbox_clone = self.apns_client_sbox.clone();

        let response_future = body

            // Hyper supports streamed requests, so we first need to
            // concatenate chunks until the request body is complete.
            .concat2()
            .map_err(|e| ServiceError::new(e.to_string()))

            // Once the body is complete, process it
            .and_then(move |body: Chunk| {
                let parsed = form_urlencoded::parse(&body).collect::<Vec<_>>();

                // Validate parameters
                if parsed.is_empty() {
                    return bad_request!("Invalid or missing parameters");
                }

                /// Iterate over parameters and find first matching key.
                /// If the key is not found, then return a HTTP 400 response.
                macro_rules! find_or_bad_request {
                    ($name:expr) => {
                        match parsed.iter().find(|&&(ref k, _)| k == $name) {
                            Some(&(_, ref v)) => v,
                            None => return bad_request!("Invalid or missing parameters"),
                        }
                    }
                }

                /// Iterate over parameters and find first matching key.
                /// If the key is not found, return a default.
                macro_rules! find_or_default {
                    ($name:expr, $default:expr) => {
                        match parsed.iter().find(|&&(ref k, _)| k == $name) {
                            Some(&(_, ref v)) => v,
                            None => $default,
                        }
                    }
                }

                // Get parameters
                let push_token = match find_or_default!("type", "gcm") {
                    "gcm" => PushToken::Gcm(GcmToken(find_or_bad_request!("token").to_string())),
                    "apns" => PushToken::Apns(ApnsToken(find_or_bad_request!("token").to_string())),
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
                    },
                };
                let (bundle_id, endpoint) = match push_token {
                    PushToken::Apns(_) => {
                        let bundle_id = Some(find_or_bad_request!("bundleid").to_owned());
                        let endpoint_str = find_or_bad_request!("endpoint");
                        let endpoint = Some(match endpoint_str.as_ref() {
                            "p" => Endpoint::Production,
                            "s" => Endpoint::Sandbox,
                            _ => return bad_request!("Invalid or missing parameters"),
                        });
                        (bundle_id, endpoint)
                    },
                    _ => (None, None),
                };

                // Send push notification
                info!("Sending push message to {} for session {} [v{}]", push_token.abbrev(), session_public_key, version);
                let push_future = match push_token {
                    PushToken::Gcm(ref token) => gcm::send_push(
                        gcm_api_key_clone,
                        token,
                        version,
                        &session_public_key,
                        gcm::Priority::High,
                        90,
                    ),
                    PushToken::Apns(ref token) => apns::send_push(
                        match endpoint.unwrap() {
                            Endpoint::Production => match apns_client_prod_clone.lock() {
                                Ok(guard) => guard,
                                Err(_) => return server_error!("Could not lock apns_client_prod_clone mutex"),
                            },
                            Endpoint::Sandbox => match apns_client_sbox_clone.lock() {
                                Ok(guard) => guard,
                                Err(_) => return server_error!("Could not lock apns_client_sbox_clone mutex"),
                            },
                        }.deref(),
                        token,
                        bundle_id.expect("bundle_id is None"),
                        version,
                        &session_public_key,
                    ),
                };

                Box::new(push_future
                    .map(|_| {
                        debug!("Success!");
                        Response::builder()
                            .status(StatusCode::NO_CONTENT)
                            .header(CONTENT_TYPE, "text/plain")
                            .body(Body::empty())
                            .unwrap()
                    })
                    .or_else(|e: SendPushError| {
                        warn!("Error: {}", e);
                        let body = "Push not successful";
                        future::ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .header(CONTENT_LENGTH, &*body.len().to_string())
                            .header(CONTENT_TYPE, "text/plain")
                            .body(Body::from(body))
                            .unwrap())
                    })
                )
            })
            .map_err(|e| ServiceError::new(e.to_string()));

        Box::new(response_future)
    }
}


#[cfg(test)]
mod tests {
    extern crate hyper;
    extern crate mockito;
    extern crate openssl;

    use super::*;

    use hyper::Body;

    use self::mockito::mock;
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
        let pem = key.private_key_to_pem().unwrap();
        pem
    }

    fn get_handler() -> (Core, PushHandler) {
        let core = Core::new().unwrap();
        let api_key = get_apns_test_key();
        let apns_client_prod = apns::create_client(
            Endpoint::Production,
            api_key.as_slice(),
            "team_id",
            "key_id",
        ).unwrap();
        let apns_client_sbox = apns::create_client(
            Endpoint::Sandbox,
            api_key.as_slice(),
            "team_id",
            "key_id",
        ).unwrap();
        let handler = PushHandler {
            gcm_api_key: "aassddff".into(),
            apns_client_prod: Arc::new(Mutex::new(apns_client_prod)),
            apns_client_sbox: Arc::new(Mutex::new(apns_client_sbox)),
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

        let req = Request::post("/push").body(Body::empty()).unwrap();
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = get_body(&mut core, resp.into_body());
        assert_eq!(&body, "Invalid content type");
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
            .body("type=apns&token=1234&session=123deadbeef&version=3&bundleid=jklö&endpoint=q".into())
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

    #[test]
    fn test_ok() {
        let _m = mock("POST", "/gcm/send")
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
            .body("type=gcm&token=aassddff&session=deadbeef&version=1".into())
            .unwrap();
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "text/plain",
        );
    }
}
