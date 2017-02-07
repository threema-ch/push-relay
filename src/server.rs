use std::net::ToSocketAddrs;
use iron::{Iron, Request, Response, IronResult, Plugin, Listening, Handler, Chain, status};
use iron::mime::{Mime, TopLevel, SubLevel};
use iron::headers::ContentType;
use iron::modifiers::Header;
use iron::error::HttpResult;
use iron_cors::CorsMiddleware;
use router::Router;
use urlencoded::UrlEncodedBody;
use ::gcm::{send_push, Priority};

pub fn serve<S, T>(api_key: S, listen_on: T) -> HttpResult<Listening>
                   where S: ToString, T: ToSocketAddrs {
    // Create new router
    let mut router = Router::new();

    // Map paths to handlers
    let handler = PushHandler { api_key: api_key.to_string() };
    router.post("/push", handler, "push");

    // Add middleware
    let mut chain = Chain::new(router);
    chain.link_around(CorsMiddleware::with_allow_any(false));

    // Start server
    Iron::new(chain).http(listen_on)
}

pub struct PushHandler {
    api_key: String,
}

impl Handler for PushHandler {

    fn handle(&self, req: &mut Request) -> IronResult<Response> {

        let content_type = Header(ContentType(Mime(TopLevel::Text, SubLevel::Plain, vec![])));

        macro_rules! bad_request {
            ($text:expr) => {
                Response::with((status::BadRequest, $text, content_type))
            };
        }

        // Parse urlencoded POST body
        let params = match req.get_ref::<UrlEncodedBody>() {
            Ok(hashmap) => hashmap,
            Err(_) => return Ok(bad_request!("Invalid content-type or missing parameters")),
        };

        // Get parameters
        macro_rules! unwrap_or_bad_request {
            ($val:expr) => {
                match $val {
                    Some(val) => match val.len() {
                        1 => val[0].clone(),
                        _ => return Ok(bad_request!("Invalid or missing parameters")),
                    },
                    None => return Ok(bad_request!("Invalid or missing parameters")),
                }
            };
        }
        let push_token = unwrap_or_bad_request!(params.get("token"));
        let session_public_key = unwrap_or_bad_request!(params.get("session"));
        let version: Option<u16> = match params.get("version") {
            // At least one version parameter was specified
            Some(val) => {
                // More than one version parameter
                if val.len() != 1 {
                    return Ok(bad_request!("You may only specify the version parameter once"));
                }
                // Exactly one version parameter
                match val[0].trim().parse::<u16>() {
                    Ok(parsed) => Some(parsed),
                    Err(e) => {
                        warn!("Got push request with invalid version param: {:?}", e);
                        return Ok(bad_request!("Invalid version parameter"))
                    },
                }
            },
            // No version parameter was specified
            None => {
                warn!("Got push request without version param");
                None
            },
        };

        // Send push notification
        info!("Sending push message to GCM for session {} [v{}]", session_public_key, match version {
            Some(v) => v.to_string(),
            None => "?".to_string(),
        });
        match send_push(&self.api_key, &push_token, version, &session_public_key, Priority::high, 45) {
            Ok(response) => {
                debug!("Success!");
                debug!("Details: {:?}", response);
                Ok(Response::with((status::NoContent, content_type)))
            }
            Err(e) => {
                warn!("Error: {}", e);
                Ok(Response::with(
                    (status::InternalServerError, "Push not successful", content_type)
                ))
            }
        }
    }

}

#[cfg(test)]
mod tests {
    extern crate iron;
    extern crate iron_test;
    extern crate mockito;

    use iron::status;
    use iron::headers::{Headers, ContentType};
    use iron::mime::{Mime, TopLevel, SubLevel};
    use self::iron_test::{request, response};
    use self::mockito::mock;
    use super::PushHandler;

    fn build_default_headers() -> Headers {
        let mut headers = Headers::new();
        headers.set(ContentType(Mime(TopLevel::Application, SubLevel::WwwFormUrlEncoded, vec![])));
        headers
    }

    /// A request without parameters should result in a HTTP 400 response.
    #[test]
    fn test_missing_param() {
        let handler = PushHandler { api_key: "asdf".into() };
        let response = request::post("http://localhost:3000/push",
                                     build_default_headers(),
                                     "",
                                     &handler).unwrap();
        let status = response.status;
        let body = response::extract_body_to_string(response);
        assert_eq!(status, Some(status::BadRequest), "{}", body);
        assert_eq!(&body, "Invalid content-type or missing parameters");
    }

    #[test]
    fn test_ok() {
        mock("POST", "/gcm/send")
            .with_status(200)
            .with_body(r#"{
                "multicast_id": 1,
                "success": 1,
                "failure": 0,
                "canonical_ids": 0,
                "results": null
            }"#)
            .create();
        let handler = PushHandler { api_key: "asdf".into() };
        let response = request::post("http://localhost:3000/push",
                                     build_default_headers(),
                                     "token=asdf&session=deadbeef&version=1",
                                     &handler).unwrap();
        let status = response.status;
        let headers = response.headers.clone();
        let body = response::extract_body_to_string(response);
        assert_eq!(status, Some(status::NoContent), "{}", body);
        assert_eq!(
            headers.get::<ContentType>(),
            Some(&ContentType(Mime(TopLevel::Text, SubLevel::Plain, vec![]))),
            "Response should set the Content-Type to `text/plain`"
        );
    }
}
