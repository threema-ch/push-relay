use std::net::ToSocketAddrs;
use iron::{Iron, Request, Response, IronResult, Plugin, Listening, Handler, Chain};
use iron::status;
use iron::error::HttpResult;
use router::Router;
use urlencoded::UrlEncodedBody;
use ::gcm::send_push;
use ::cors::CorsMiddleware;

pub fn serve<S, T>(api_key: S, listen_on: T, cors_hosts: Vec<String>) -> HttpResult<Listening>
                   where S: ToString, T: ToSocketAddrs {
    // Create new router
    let mut router = Router::new();

    // Map paths to handlers
    let handler = PushHandler { api_key: api_key.to_string() };
    router.post("/push", handler, "push");

    // Add middleware
    let mut chain = Chain::new(router);
    chain.link_after(CorsMiddleware::new(cors_hosts));

    // Start server
    Iron::new(chain).http(listen_on)
}

pub struct PushHandler {
    api_key: String,
}

impl Handler for PushHandler {

    fn handle(&self, req: &mut Request) -> IronResult<Response> {
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

        info!("Sending push message to GCM for session {}", session_public_key);
        match send_push(&self.api_key, &push_token, &session_public_key) {
            Ok(response) => {
                debug!("Success!");
                debug!("Details: {:?}", response);
                Ok(Response::with(status::NoContent))
            }
            Err(e) => {
                warn!("Error: {}", e);
                Ok(Response::with((status::InternalServerError, "Push not successful")))
            }
        }
    }

}
