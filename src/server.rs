use std::net::SocketAddr;

use futures::Stream;
use futures::future::{self, Future};
use hyper::{Error as HyperError, Method, StatusCode};
use hyper::header::{ContentLength, ContentType};
use hyper::server::{Http, Request, Response, Service};
use tokio_core::reactor::{Core, Handle};
use url::form_urlencoded;

use ::gcm::{send_push, Priority};
use ::utils::BoxedFuture;


/// Start the server and run infinitely.
pub fn serve<S>(
    api_key: S,
    listen_on: SocketAddr,
) -> Result<(), HyperError> where S: ToString {
    // TODO: CSRF

    // Create reactor loop
    let mut core = Core::new().expect("Could not start event loop");
    let handle1 = core.handle();
    let handle2 = core.handle();
    let handle3 = core.handle();

    // Create server
    let serve = Http::new().serve_addr_handle(&listen_on, &handle1, || {
        Ok(PushHandler {
            api_key: api_key.to_string(),
            handle: handle2.clone(),
        })
    })?;

    // Start server
    let server = serve.for_each(move |conn| {
        handle3.spawn(
            conn.map(|_| ()).map_err(|e| error!("Serve error: {}", e))
        );
        Ok(())
    });
    core.run(server)
}

pub struct PushHandler {
    api_key: String,
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
        let api_key_clone = self.api_key.clone();
        let handle_clone = self.handle.clone();
        Box::new(
            body
                // Hyper supports streamed requests, so we first need to
                // concatenate chunks until the request body is complete.
                .concat2()

                // Once the body is complete, process it
                .and_then(|body| {
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

                    // Get parameters
                    let push_token = find_or_bad_request!("token");
                    let session_public_key = find_or_bad_request!("session");
                    let version_string = find_or_bad_request!("version");
                    let version: u16 = match version_string.trim().parse::<u16>() {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            warn!("Got push request with invalid version param: {:?}", e);
                            return bad_request!("Invalid or missing parameters");
                        },
                    };

                    // Send push notification
                    info!("Sending push message to GCM for session {} [v{}]", session_public_key, version);
                    let push_future = send_push(
                        handle_clone,
                        api_key_clone,
                        &push_token,
                        version,
                        &session_public_key,
                        Priority::high,
                        90,
                    )
                    .map(|resp| {
                        debug!("Success!");
                        debug!("Details: {:?}", resp);
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
                    });

                    boxed!(push_future)
                })
        ) as BoxedFuture<_, _>
    }
}

//

#[cfg(test)]
mod tests {
    extern crate hyper;
    extern crate mockito;

    use super::*;

    use std::str::FromStr;

    use hyper::{Body, Uri};

    use self::mockito::mock;


    fn get_body(core: &mut Core, body: Body) -> String {
        let bytes = core.run(body.concat2()).unwrap();
        ::std::str::from_utf8(&bytes).unwrap().to_string()
    }

    /// Handle invalid paths
    #[test]
    fn test_invalid_path() {
        let mut core = Core::new().unwrap();
        let handler = PushHandler { api_key: "aassddff".into(), handle: core.handle() };

        let req = Request::new(Method::Post, Uri::from_str("/larifari").unwrap());
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::NotFound);
    }

    /// Handle invalid methods
    #[test]
    fn test_invalid_method() {
        let mut core = Core::new().unwrap();
        let handler = PushHandler { api_key: "aassddff".into(), handle: core.handle() };

        let req = Request::new(Method::Get, Uri::from_str("/push").unwrap());
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::MethodNotAllowed);
    }

    /// Handle invalid request content type
    #[test]
    fn test_invalid_contenttype() {
        let mut core = Core::new().unwrap();
        let handler = PushHandler { api_key: "aassddff".into(), handle: core.handle() };

        let req = Request::new(Method::Post, Uri::from_str("/push").unwrap());
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::BadRequest);
        let body = get_body(&mut core, resp.body());
        assert_eq!(&body, "Invalid content type");
    }

    /// A request without parameters should result in a HTTP 400 response.
    #[test]
    fn test_no_params() {
        let mut core = Core::new().unwrap();
        let handler = PushHandler { api_key: "aassddff".into(), handle: core.handle() };

        let mut req = Request::new(Method::Post, Uri::from_str("/push").unwrap());
        req.headers_mut().set(ContentType::form_url_encoded());
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::BadRequest);
        let body = get_body(&mut core, resp.body());
        assert_eq!(&body, "Invalid or missing parameters");
    }

    /// A request wit missing parameters should result in a HTTP 400 response.
    #[test]
    fn test_missing_params() {
        let mut core = Core::new().unwrap();
        let handler = PushHandler { api_key: "aassddff".into(), handle: core.handle() };

        let mut req = Request::new(Method::Post, Uri::from_str("/push").unwrap());
        req.headers_mut().set(ContentType::form_url_encoded());
        req.set_body("token=1234");
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

        let mut core = Core::new().unwrap();
        let handler = PushHandler { api_key: "aassddff".into(), handle: core.handle() };

        let mut req = Request::new(Method::Post, Uri::from_str("/push").unwrap());
        req.headers_mut().set(ContentType::form_url_encoded());
        req.set_body("token=aassddff&session=deadbeef&version=1");
        let resp = core.run(handler.call(req)).unwrap();

        assert_eq!(resp.status(), StatusCode::NoContent);
        assert_eq!(resp.headers().get::<ContentType>(), Some(&ContentType::plaintext()));
    }
}
