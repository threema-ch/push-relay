//! # GCM Push Relay
//! 
//! This server accepts push requests via HTTPS and notifies the GCM push
//! service.

extern crate chrono;
extern crate clap;
extern crate env_logger;
extern crate futures;
extern crate hyper;
extern crate ini;
#[macro_use] extern crate log;
extern crate mime;
#[macro_use] extern crate quick_error;
extern crate rustc_serialize;
extern crate tokio_core;
extern crate url;

#[cfg(test)] extern crate mockito;

#[macro_use] mod utils;
mod errors;
mod gcm;
mod server;

use std::net::SocketAddr;
use std::process;

use clap::{App, Arg};
use ini::Ini;

const NAME: &'static str = "push-relay";
const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const DESCRIPTION: &'static str = "This server accepts push requests via HTTP and notifies the GCM push service.";

fn main() {
    env_logger::init();

    let matches = App::new(NAME)
        .version(VERSION)
        .about(DESCRIPTION)
        .arg(Arg::with_name("listen")
             .short("l")
             .long("listen")
             .value_name("host:port")
             .help("The ip/port to listen on. Default: 127.0.0.1:3000."))
        .arg(Arg::with_name("config")
             .short("c")
             .long("config")
             .value_name("path")
             .help("Path to a configfile. Default: config.ini."))
        .get_matches();

    let listen = matches.value_of("listen").unwrap_or("127.0.0.1:3000");
    let addr: SocketAddr = listen.parse().unwrap_or_else(|e| {
        error!("Invalid listen address: {} ({})", listen, e);
        process::exit(1);
    });

    let configfile = matches.value_of("config").unwrap_or("config.ini");

    // Load config file
    let config = Ini::load_from_file(configfile).unwrap_or_else(|e| {
        error!("Could not open config file: {}", e);
        process::exit(1);
    });

    // Determine GCM API key
    let config_gcm = config.section(Some("gcm".to_owned())).unwrap_or_else(|| {
        error!("Invalid config file: No [gcm] section in {}", configfile);
        process::exit(2);
    });
    let api_key = config_gcm.get("api_key").unwrap_or_else(|| {
        error!("Invalid config file: No 'api_key' key in [gcm] section in {}", configfile);
        process::exit(2);
    });

    info!("Starting Push Relay Server {} on {}", VERSION, &addr);
    server::serve(api_key, addr).unwrap_or_else(|e| {
        error!("Could not start relay server: {}", e);
        process::exit(3);
    });
}
