use std::error;
use std::fmt;

use a2::error::Error as A2Error;
use hyper::Error as HyperError;
use reqwest::Error as ReqwestError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PushRelayError {
    #[error("APNs error: {0}")]
    Apns(#[from] A2Error),

    #[error("Hyper error: {0}")]
    Hyper(#[from] HyperError),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] ReqwestError),
}

#[derive(Error, Debug)]
pub enum SendPushError {
    #[error("Push message could not be sent: {0}")]
    SendError(String),

    // Caused by remote server. Retrying might help.
    #[error("Push message could not be processed: {0}")]
    ProcessingRemoteError(String),

    // Caused by client (e.g. bad push token). Retrying would probably not help.
    #[error("Push message could not be processed: {0}")]
    ProcessingClientError(String),

    // Server authentication error. Retrying might help.
    #[error("Authentication error: {0}")]
    AuthError(String),

    #[error("Other: {0}")]
    Other(String),
}

#[derive(Error, Debug)]
pub enum InfluxdbError {
    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Database not found")]
    DatabaseNotFound,

    #[error("Other: {0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServiceError(String);

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
