use std::convert::Into;
use std::net::SocketAddr;
use std::rc::Rc;

use apns2::client::{Endpoint, Client as ApnsClient};
use futures::Stream;
use futures::future::{self, Future};
use hyper::{Error as HyperError, Method, StatusCode};
use hyper::header::{ContentLength, ContentType};
use hyper::server::{Http, Request, Response, Service};
use tokio_core::reactor::{Core, Handle};
use url::form_urlencoded;

use ::errors::PushError;
use ::push::{PushToken, GcmToken, ApnsToken};
use ::push::{gcm, apns};
use ::utils::BoxedFuture;


/// Start the server and run infinitely.
pub fn serve (
    gcm_api_key: &str,
    apns_api_key: Vec<u8>,
    apns_team_id: &str,
    apns_key_id: &str,
    listen_on: SocketAddr,
) -> Result<(), PushError> {
    // TODO: CSRF

    // Create reactor loop
    let mut core = Core::new().expect("Could not start event loop");

    // Create APNs client
    let apns_client_prod = Rc::new(apns::create_client(
        core.handle(),
        Endpoint::Production,
        apns_api_key.as_slice(),
        apns_team_id,
        apns_key_id,
    )?);
    let apns_client_sbox = Rc::new(apns::create_client(
        core.handle(),
        Endpoint::Sandbox,
        apns_api_key.as_slice(),
        apns_team_id,
        apns_key_id,
    )?);

    // Create server
    let handle = core.handle();
    let serve = Http::new().serve_addr_handle(&listen_on, &core.handle(), || {
        Ok(PushHandler {
            gcm_api_key: gcm_api_key.to_string(),
            apns_client_prod: apns_client_prod.clone(),
            apns_client_sbox: apns_client_sbox.clone(),
            handle: handle.clone(),
        })
    })?;

    // Start server
    let handle = core.handle();
    let server = serve.for_each(move |conn| {
        handle.spawn(
            conn.map(|_| ()).map_err(|e| error!("Serve error: {}", e))
        );
        Ok(())
    });
    core.run(server).map_err(Into::into)
}

/// The server endpoint that accepts incoming push requests.
pub struct PushHandler {
    gcm_api_key: String,
    apns_client_prod: Rc<ApnsClient>,
    apns_client_sbox: Rc<ApnsClient>,
    handle: Handle,
}

impl Service for PushHandler {

    // Boilerplate for hooking up hyper's server types
    type Request = Request;
    type Response = Response;
    type Error = HyperError;

    // The future representing the eventual response
    type Future = BoxedFuture<Self::Response, Self::Error>;

    fn call(&self, req: Request) -> Self::Future {
        let (method, uri, _version, headers, body) = req.deconstruct();
        info!("{} {}", method, uri);

        // Verify path
        if uri.path() != "/push" {
            return Box::new(future::ok(
                Response::new()
                    .with_status(StatusCode::NotFound)
            ));
        }

        // Verify method
        if method != Method::Post {
            return Box::new(future::ok(
                Response::new()
                    .with_status(StatusCode::MethodNotAllowed)
            ));
        }

        /// Create a "bad request" response.
        macro_rules! bad_request {
            ($text:expr) => {
                boxed!(future::ok(
                    Response::new()
                        .with_status(StatusCode::BadRequest)
                        .with_header(ContentType::plaintext())
                        .with_header(ContentLength($text.len() as u64))
                        .with_body($text)
                ))
            }
        }

        // Verify content type
        let content_type = headers.get::<ContentType>();
        match content_type {
            Some(ct) if ct.type_() == "application"
                     && ct.subtype() == "x-www-form-urlencoded" => { /* ok */ },
            _ => return bad_request!("Invalid content type"),
        };
        
        // Parse request body
        let gcm_api_key_clone = self.gcm_api_key.clone();
        let handle_clone = self.handle.clone();
        let apns_client_prod_clone = self.apns_client_prod.clone();
        let apns_client_sbox_clone = self.apns_client_sbox.clone();
        Box::new(
            body
                // Hyper supports streamed requests, so we first need to
                // concatenate chunks until the request body is complete.
                .concat2()

                // Once the body is complete, process it
                .and_then(move |body| {
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
                            handle_clone,
                            gcm_api_key_clone,
                            token,
                            version,
                            &session_public_key,
                            gcm::Priority::High,
                            90,
                        ),
                        PushToken::Apns(ref token) => apns::send_push(
                            match endpoint.unwrap() {
                                Endpoint::Production => &apns_client_prod_clone,
                                Endpoint::Sandbox => &apns_client_sbox_clone,
                            },
                            token,
                            bundle_id.expect("bundle_id is None"),
                            version,
                            &session_public_key,
                        ),
                    };

                    boxed!(push_future
                        .map(|_| {
                            debug!("Success!");
                            Response::new()
                                .with_status(StatusCode::NoContent)
                                .with_header(ContentLength(0))
                                .with_header(ContentType::plaintext())
                        })
                        .or_else(|e| {
                            warn!("Error: {}", e);
                            let body = "Push not successful";
                            future::ok(Response::new()
                                .with_status(StatusCode::InternalServerError)
                                .with_header(ContentType::plaintext())
                                .with_header(ContentLength(body.len() as u64))
                                .with_body(body))
                        })
                    )
                })
        ) as BoxedFuture<_, _>
    }
}

//

#[cfg(test)]
mod tests {
    extern crate hyper;
    extern crate mockito;
    extern crate openssl;

    use super::*;

    use std::str::FromStr;

    use hyper::{Body, Uri};

    use self::mockito::mock;
    use self::openssl::ec::{EcKey, EcGroup};
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
            core.handle(), Endpoint::Production,
            api_key.as_slice(), "team_id", "key_id",
        ).unwrap();
        let apns_client_sbox = apns::create_client(
            core.handle(), Endpoint::Sandbox,
            api_key.as_slice(), "team_id", "key_id",
        ).unwrap();
        let handler = PushHandler {
            gcm_api_key: "aassddff".into(),
            apns_client_prod: Rc::new(apns_client_prod),
            apns_client_sbox: Rc::new(apns_client_sbox),
            handle: core.handle(),
        };
        (core, handler)
    }

    /// Handle invalid paths
    #[test]
    fn test_invalid_path() {
        let (mut core, handler) = get_handler();

        let req = Request::new(Method::Post, Uri::from_str("/larifari").unwrap());
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::NotFound);
    }

    /// Handle invalid methods
    #[test]
    fn test_invalid_method() {
        let (mut core, handler) = get_handler();

        let req = Request::new(Method::Get, Uri::from_str("/push").unwrap());
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::MethodNotAllowed);
    }

    /// Handle invalid request content type
    #[test]
    fn test_invalid_contenttype() {
        let (mut core, handler) = get_handler();

        let req = Request::new(Method::Post, Uri::from_str("/push").unwrap());
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::BadRequest);
        let body = get_body(&mut core, resp.body());
        assert_eq!(&body, "Invalid content type");
    }

    /// A request without parameters should result in a HTTP 400 response.
    #[test]
    fn test_no_params() {
        let (mut core, handler) = get_handler();

        let mut req = Request::new(Method::Post, Uri::from_str("/push").unwrap());
        req.headers_mut().set(ContentType::form_url_encoded());
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::BadRequest);
        let body = get_body(&mut core, resp.body());
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request with missing parameters should result in a HTTP 400 response.
    #[test]
    fn test_missing_params() {
        let (mut core, handler) = get_handler();

        let mut req = Request::new(Method::Post, Uri::from_str("/push").unwrap());
        req.headers_mut().set(ContentType::form_url_encoded());
        req.set_body("token=1234");
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::BadRequest);
        let body = get_body(&mut core, resp.body());
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request with missing parameters should result in a HTTP 400 response.
    #[test]
    fn test_missing_params_apns() {
        let (mut core, handler) = get_handler();

        let mut req = Request::new(Method::Post, Uri::from_str("/push").unwrap());
        req.headers_mut().set(ContentType::form_url_encoded());
        req.set_body("type=apns&token=1234&session=123deadbeef&version=3");
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::BadRequest);
        let body = get_body(&mut core, resp.body());
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request with bad parameters should result in a HTTP 400 response.
    #[test]
    fn test_bad_endpoint() {
        let (mut core, handler) = get_handler();

        let mut req = Request::new(Method::Post, Uri::from_str("/push").unwrap());
        req.headers_mut().set(ContentType::form_url_encoded());
        req.set_body("type=apns&token=1234&session=123deadbeef&version=3&bundleid=asdf&endpoint=q");
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::BadRequest);
        let body = get_body(&mut core, resp.body());
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request wit missing parameters should result in a HTTP 400 response.
    #[test]
    fn test_bad_token_type() {
        let (mut core, handler) = get_handler();

        let mut req = Request::new(Method::Post, Uri::from_str("/push").unwrap());
        req.headers_mut().set(ContentType::form_url_encoded());
        req.set_body("type=abc&token=aassddff&session=deadbeef&version=1");
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::BadRequest);
        let body = get_body(&mut core, resp.body());
        assert_eq!(&body, "Invalid or missing parameters");
    }

    #[test]
    fn test_ok() {
        let _m = mock("POST", "/gcm/send")
            .with_status(200)
            .with_body(r#"{
                "multicast_id": 1,
                "success": 1,
                "failure": 0,
                "canonical_ids": 0,
                "results": null
            }"#)
            .create();

        let (mut core, handler) = get_handler();

        let mut req = Request::new(Method::Post, Uri::from_str("/push").unwrap());
        req.headers_mut().set(ContentType::form_url_encoded());
        req.set_body("type=gcm&token=aassddff&session=deadbeef&version=1");
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::NoContent);
        assert_eq!(resp.headers().get::<ContentType>(), Some(&ContentType::plaintext()));
    }
}
