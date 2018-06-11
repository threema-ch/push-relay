use std::error;
use std::fmt;

use a2::error::Error as A2Error;
use hyper::error::Error as HyperError;

quick_error! {
    #[derive(Debug)]
    pub enum PushRelayError {
        ApnsError(err: A2Error) {
            from()
            display("APNs error: {}", err)
            cause(err)
        }
        HyperError(err: HyperError) {
            from()
            display("Hyper error: {}", err)
            cause(err)
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum SendPushError {
        SendError(msg: String) {
            display("Push message could not be sent: {}", msg)
        }
        ProcessingError(msg: String) {
            display("Push message could not be processed: {}", msg)
        }
        Other(msg: String) {
            display("Other: {}", msg)
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum InfluxdbError {
        Http(msg: String) {
            display("HTTP error: {}", msg)
        }
        DatabaseNotFound {
            display("Database not found")
        }
        Other(msg: String) {
            display("Other: {}", msg)
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServiceError(String);

impl ServiceError {
    pub fn new(msg: String) -> Self {
        ServiceError(msg)
    }
}
impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ServiceError: {}", self.0)
    }
}

impl error::Error for ServiceError {
    fn description(&self) -> &str {
        &self.0
    }
}
