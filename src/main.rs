//! # GCM Push Relay
//! 
//! This server accepts push requests via HTTPS and notifies the GCM push
//! service.

extern crate chrono;
extern crate clap;
extern crate env_logger;
extern crate hyper;
extern crate ini;
extern crate iron;
extern crate router;
extern crate rustc_serialize;
extern crate urlencoded;
#[macro_use] extern crate log;
#[macro_use] extern crate quick_error;

mod server;
mod gcm;
mod errors;

use std::process;
use clap::{App, Arg};
use ini::Ini;

const NAME: &'static str = "push-relay";
const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const DESCRIPTION: &'static str = "This server accepts push requests via HTTP and notifies the GCM push service.";

fn main() {
    env_logger::init().expect("Could not initialize env_logger");

    let matches = App::new(NAME)
        .version(VERSION)
        .about(DESCRIPTION)
        .arg(Arg::with_name("listen")
             .short("l")
             .long("listen")
             .value_name("host:port")
             .help("The host/port to listen on. Default: localhost:3000."))
        .arg(Arg::with_name("config")
             .short("c")
             .long("config")
             .value_name("path")
             .help("Path to a configfile. Default: config.ini."))
        .get_matches();

    let listen = matches.value_of("listen").unwrap_or("localhost:3000");
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

    info!("Starting Push Relay Server on {}", &listen);
    server::serve(api_key, listen).unwrap_or_else(|e| {
        error!("Could not start relay server: {}", e);
        process::exit(3);
    });
}
