use std::str::from_utf8;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::{
    header::{AUTHORIZATION, CONTENT_TYPE},
    Body, Client, StatusCode,
};

use crate::{errors::InfluxdbError, http_client::make_client};

/// InfluxDB client.
#[derive(Debug)]
pub struct Influxdb {
    connection_string: String,
    authorization: String,
    db: String,
    client: Client,
    hostname: String,
}

type InfluxdbResult = Result<(), InfluxdbError>;

impl Influxdb {
    /// Create a new InfluxDB connection.
    pub fn new(
        connection_string: String,
        user: &str,
        pass: &str,
        db: String,
    ) -> Result<Self, String> {
        // Initialize HTTP client
        let client =
            make_client(90).map_err(|e| format!("Failed to initialize http client: {e}"))?;

        // Determine hostname
        let hostname = hostname::get().ok().map_or_else(
            || "unknown".to_string(),
            |os_string| os_string.to_string_lossy().into_owned(),
        );

        // Determine authorization header
        let authorization = Self::get_authorization_header(user, pass);

        Ok(Self {
            connection_string,
            authorization,
            db,
            client,
            hostname,
        })
    }

    fn get_authorization_header(user: &str, pass: &str) -> String {
        let bytes = format!("{user}:{pass}").into_bytes();
        format!("Basic {}", BASE64.encode(bytes))
    }

    /// Create the database.
    pub async fn create_db(&self) -> InfluxdbResult {
        debug!("Creating InfluxDB database \"{}\"", self.db);

        // Prepare body
        let body: Body = format!("q=CREATE%20DATABASE%20{}", self.db).into();

        // Send request
        let response = self
            .client
            .post(format!("{}/query", &self.connection_string))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, &self.authorization)
            .body(body)
            .send()
            .await
            .map_err(|e| InfluxdbError::Http(format!("Request failed: {e}")))?;

        // Handle response status codes
        match response.status() {
            StatusCode::OK => Ok(()),
            StatusCode::BAD_REQUEST => {
                let body = response
                    .bytes()
                    .await
                    .ok()
                    .and_then(|body| from_utf8(&body).ok().map(|s| s.to_string()))
                    .unwrap_or_else(|| "[invalid utf8 body]".to_string());
                Err(InfluxdbError::Other(body))
            }
            status => Err(InfluxdbError::Http(format!(
                "Unexpected status code: {status}"
            ))),
        }
    }

    async fn log(&self, body: impl Into<Body>) -> InfluxdbResult {
        let body: Body = body.into();

        // Send request
        let response = self
            .client
            .post(format!("{}/write?db={}", &self.connection_string, &self.db))
            .header(AUTHORIZATION, &self.authorization)
            .body(body)
            .send()
            .await
            .map_err(|e| InfluxdbError::Http(format!("Request failed: {e}")))?;

        // Handle response status codes
        match response.status() {
            StatusCode::NO_CONTENT => Ok(()),
            StatusCode::NOT_FOUND => Err(InfluxdbError::DatabaseNotFound),
            status => Err(InfluxdbError::Http(format!(
                "Unexpected status code: {status}"
            ))),
        }
    }

    /// Log the starting of the push relay server.
    pub async fn log_started(&self) -> InfluxdbResult {
        debug!("Logging \"started\" event to InfluxDB");
        self.log(format!("started,host={} value=1", self.hostname))
            .await
    }

    /// Log a push (either successful or failed) to InfluxDB.
    pub async fn log_push(&self, push_type: &str, version: u16, success: bool) -> InfluxdbResult {
        let success_str = if success { "true" } else { "false" };
        let push_type = push_type.to_ascii_lowercase();
        debug!(
            "Logging \"push\" event (success = \"{success_str}\", {push_type}, v{version}) to InfluxDB"
        );
        let hostname = self.hostname.as_str();
        self.log(format!(
            "push,host={hostname},type={push_type},version={version},success={success_str} value=1"
        ))
        .await
    }
}
