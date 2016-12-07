//! A CORS middleware for Iron.
//! 
//! See https://www.html5rocks.com/static/images/cors_server_flowchart.png for
//! reference.
//! 
//! Preflight requests are not yet supported.

use iron::{Request, Response, IronResult};
use iron::{AfterMiddleware};
use iron::{headers};

pub struct CorsMiddleware {
    allowed_hosts: Vec<String>,
}

impl CorsMiddleware {
    pub fn new(allowed_hosts: Vec<String>) -> Self {
        CorsMiddleware { allowed_hosts: allowed_hosts }
    }
}

impl AfterMiddleware for CorsMiddleware {
    fn after(&self, req: &mut Request, mut res: Response) -> IronResult<Response> {
        match req.headers.get::<headers::Origin>() {
            Some(origin) => {
                if self.allowed_hosts.contains(&origin.host.hostname) {
                    res.headers.set(headers::AccessControlAllowOrigin::Value(origin.host.hostname.clone()));
                }
            },
            None => warn!("Not a valid CORS request: Missing Origin header"),
        }
        Ok(res)
    }
}

