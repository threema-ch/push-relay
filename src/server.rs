use std::net::ToSocketAddrs;
use iron::{Iron, Request, Response, IronResult, Listening, status};
use iron::error::HttpResult;
use router::Router;

fn handler(req: &mut Request) -> IronResult<Response> {
    Ok(Response::with((status::Ok, "Hello World")))
}

pub fn serve<T: ToSocketAddrs>(listen_on: T) -> HttpResult<Listening> {
    let mut router = Router::new();

    router.post("/push", handler, "push");

    Iron::new(router).http(listen_on)
}
