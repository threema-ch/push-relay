use apns_h2::error::Error as A2Error;
use axum::response::{IntoResponse, Response};
use reqwest::{Error as ReqwestError, StatusCode};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum InitError {
    #[error("APNs init error: {0}")]
    Apns(#[source] A2Error),

    #[error("Reqwest init error: {0}")]
    Reqwest(#[source] ReqwestError),

    #[error("FCM init error: {0}")]
    Fcm(#[source] anyhow::Error),

    #[error("I/O error: {reason}: {source}")]
    Io {
        reason: &'static str,
        source: std::io::Error,
    },
}

#[derive(Error, Debug)]
// RemoteError
pub enum SendPushError {
    /// The request could not be sent
    #[error("Push message could not be sent: {0}")]
    SendError(#[source] reqwest::Error),

    /// Caused by remote server. Retrying might help.
    #[error("Push message could not be processed: {0}")]
    RemoteServer(String),

    /// Caused by client (e.g. bad push token). Retrying would probably not help.
    #[error("Push message could not be processed: {0}")]
    RemoteClient(String),

    /// Server authentication error. Retrying might help.
    #[error("Authentication error: {0}")]
    RemoteAuth(String),

    #[error("Unspecified internal error: {0}")]
    Internal(String),
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
