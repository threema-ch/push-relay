use a2::error::Error as A2Error;
use axum::response::{IntoResponse, Response};
use reqwest::{Error as ReqwestError, StatusCode};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PushRelayError {
    #[error("APNs error: {0}")]
    Apns(#[from] A2Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] ReqwestError),

    #[error("I/O error: {reason}: {source}")]
    IoError {
        reason: &'static str,
        source: std::io::Error,
    },
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

/// Request handling error that is converted into an error response.
///
/// Currently all error variants result in a "HTTP 400 Bad Request" response.
#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Missing content type")]
    MissingContentType,
    #[error("Invalid content type: {0}")]
    InvalidContentType(String),
    #[error("Missing parameters")]
    MissingParams,
    #[error("Invalid parameters")]
    InvalidParams,
}

// Tell axum how to convert `ServiceError` into a response.
impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, self.to_string()).into_response()
    }
}
