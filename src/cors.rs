//! A CORS middleware for Iron.
//!
//! See https://www.html5rocks.com/static/images/cors_server_flowchart.png for
//! reference.
//!
//! The middleware will return `HTTP 400 Bad Request` if the Origin host is
//! missing or not allowed.
//!
//! Preflight requests are not yet supported.

use iron::{Request, Response, IronResult, AroundMiddleware, Handler};
use iron::{headers, status};

pub struct CorsMiddleware {
    allowed_hosts: Vec<String>,
}

impl CorsMiddleware {
    pub fn new(allowed_hosts: Vec<String>) -> Self {
        CorsMiddleware { allowed_hosts: allowed_hosts }
    }
}

impl AroundMiddleware for CorsMiddleware {
    fn around(self, handler: Box<Handler>) -> Box<Handler> {
        Box::new(CorsHandler { handler: handler, allowed_hosts: self.allowed_hosts.clone() })
    }
}

struct CorsHandler {
    handler: Box<Handler>,
    allowed_hosts: Vec<String>,
}

impl Handler for CorsHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {
        // Extract origin header
        let origin = match req.headers.get::<headers::Origin>() {
            Some(origin) => origin.clone(),
            None => {
                warn!("Not a valid CORS request: Missing Origin header");
                return Ok(Response::with((status::BadRequest, "Invalid CORS request: Origin header missing")));
            }
        };

        // Verify origin header
        if self.allowed_hosts.contains(&origin.host.hostname) {

            // Everything OK, process request
            let mut res = try!(self.handler.handle(req));

            // Add Access-Control-Allow-Origin header to response
            let header = match origin.host.port {
                Some(port) => format!("{}://{}:{}", &origin.scheme, &origin.host.hostname, &port),
                None => format!("{}://{}", &origin.scheme, &origin.host.hostname),
            };
            res.headers.set(headers::AccessControlAllowOrigin::Value(header));

            Ok(res)
        } else {
            warn!("Got disallowed CORS request from {}", &origin.host.hostname);
            Ok(Response::with((status::BadRequest, "Invalid CORS request: Origin not allowed")))
        }
    }
}
