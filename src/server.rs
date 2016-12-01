use std::net::ToSocketAddrs;
use iron::{Iron, Request, Response, IronResult, Plugin, Listening, status};
use iron::error::HttpResult;
use router::Router;
use urlencoded::UrlEncodedBody;
use ::gcm::send_push;

/// Immediately return a "HTTP 400 Bad Request" response with the specified
/// error message as JSON in the response body.

fn handler(req: &mut Request) -> IronResult<Response> {
    // Parse urlencoded POST body
    let params = match req.get_ref::<UrlEncodedBody>() {
        Ok(hashmap) => hashmap,
        Err(_) => return Ok(Response::with((status::BadRequest, "Invalid or missing parameters"))),
    };

    // Get parameters
    macro_rules! unwrap_or_bad_request {
        ($val:expr) => {
            match $val {
                Some(val) => match val.len() {
                    1 => val[0].clone(),
                    _ => return Ok(Response::with((status::BadRequest, "Invalid or missing parameters"))),
                },
                None => return Ok(Response::with((status::BadRequest, "Invalid or missing parameters"))),
            }
        };
    }
    let push_token = unwrap_or_bad_request!(params.get("token"));
    let session_public_key = unwrap_or_bad_request!(params.get("session"));

    println!("Sending push message to GCM:\n  > {}\n  > Session: {}", push_token, session_public_key);
    match send_push("TODO", &push_token, &session_public_key) {
        Ok(response) => {
            println!("  => Success!");
            println!("  => Details: {:?}", response);
            Ok(Response::with(status::NoContent))
        }
        Err(e) => {
            println!("  => Error: {}", e);
            Ok(Response::with((status::InternalServerError, "Push not successful")))
        }
    }
}

pub fn serve<T: ToSocketAddrs>(listen_on: T) -> HttpResult<Listening> {
    // Create new router
    let mut router = Router::new();

    // Map paths to handlers
    router.post("/push", handler, "push");

    // Start server
    Iron::new(router).http(listen_on)
}
