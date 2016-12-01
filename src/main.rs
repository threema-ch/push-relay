//! # GCM Push Relay
//! 
//! This server accepts push requests via HTTPS and notifies the GCM push
//! service.

extern crate chrono;
extern crate clap;
extern crate hyper;
extern crate iron;
extern crate router;
extern crate rustc_serialize;
extern crate urlencoded;
#[macro_use] extern crate quick_error;

mod server;
mod gcm;
mod errors;

use clap::{App, Arg};

const NAME: &'static str = "push-relay";
const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const DESCRIPTION: &'static str = "This server accepts push requests via HTTP and notifies the GCM push service.";

fn main() {
    let matches = App::new(NAME)
        .version(VERSION)
        .about(DESCRIPTION)
        .arg(Arg::with_name("listen")
             .short("l")
             .long("listen")
             .value_name("host:port")
             .help("The host/port to listen on. Default: localhost:3000."))
        .get_matches();

    let listen = matches.value_of("listen").unwrap_or("localhost:3000");
    println!("Starting Push Relay Server on {}", &listen);
    server::serve(listen).unwrap();
}
