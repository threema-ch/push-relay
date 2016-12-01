//! # GCM Push Relay
//! 
//! This server accepts push requests via HTTPS and notifies the GCM push
//! service.

extern crate chrono;
extern crate hyper;
extern crate iron;
extern crate router;
extern crate rustc_serialize;
extern crate urlencoded;
#[macro_use] extern crate quick_error;

mod server;
mod gcm;
mod errors;

fn main() {
    let listen = "localhost:3000";
    println!("Starting Push Relay Server on {}", &listen);
    server::serve(listen).unwrap();
}
