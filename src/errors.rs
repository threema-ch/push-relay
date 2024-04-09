use a2::error::Error as A2Error;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use reqwest::Error as ReqwestError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PushRelayError {
    #[error("APNs error: {0}")]
    Apns(#[from] A2Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] ReqwestError),

    #[error("{reason}: {source}")]
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

#[derive(Debug)]
pub struct ServiceError(anyhow::Error);

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

impl<E> From<E> for ServiceError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
