use std::str::from_utf8;
use std::time::Duration;

use base64;
use futures::Stream;
use futures::future::{self, Future, Either};
use hostname::get_hostname;
use http::{Request, Response};
use http::header::{CONTENT_TYPE, AUTHORIZATION};
use hyper::{Body, Client, StatusCode, Uri};
use hyper::client::HttpConnector;
use hyper_tls::HttpsConnector;

use ::errors::InfluxdbError;


#[derive(Debug)]
pub struct Influxdb {
    connection_string: String,
    authorization: String,
    db: String,
    client: Client<HttpsConnector<HttpConnector>>,
    hostname: String,
}

impl Influxdb {
    /// Create a new InfluxDB connection.
    pub fn new(
        connection_string: String,
        user: String,
        pass: String,
        db: String,
    ) -> Result<Self, String> {
        // Initialize HTTP client
        let https_connector = HttpsConnector::new(4)
            .map_err(|e| format!("Could not create HttpsConnector: {}", e))?;
        let client = Client::builder()
            .keep_alive(true)
            .keep_alive_timeout(Some(Duration::from_secs(90)))
            .build(https_connector);

        // Determine hostname
        let hostname = get_hostname().unwrap_or_else(|| "unknown".into());

        // Determine authorization header
        let authorization = Influxdb::get_authorization_header(&user, &pass);

        Ok(Influxdb {
            connection_string,
            authorization,
            db,
            client,
            hostname,
        })
    }

    fn get_authorization_header(user: &str, pass: &str) -> String {
        let bytes = format!("{}:{}", user, pass).into_bytes();
        let encoded = base64::encode(&bytes);
        format!("Basic {}", encoded)
    }

    /// Create the database.
    pub fn create_db(&self) -> impl Future<Item=(), Error=InfluxdbError> {
        debug!("Creating InfluxDB database \"{}\"", self.db);

        // Build response future
        let uri: Uri = format!("{}/query", &self.connection_string).parse().unwrap();
        let body: Body = format!("q=CREATE%20DATABASE%20{}", self.db).into();
        let response_future = self.client
            .request(
                Request::post(uri)
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(AUTHORIZATION, &*self.authorization)
                    .body(body)
                    .unwrap()
            )
            .map_err(|e| InfluxdbError::Http(format!("Request failed: {}", e)));

        response_future.and_then(move |response: Response<Body>| match response.status() {
            StatusCode::OK => Either::A(future::ok(())),
            StatusCode::BAD_REQUEST => Either::B(
                response
                    .into_body()
                    .concat2()
                    .map_err(|e| InfluxdbError::Http(format!("Cannot read response body: {}", e)))
                    .and_then(|text| Err(InfluxdbError::Other(
                        from_utf8(&*text).unwrap_or("[invalid utf8 body]").to_string()
                    )))
            ),
            status => Either::A(future::err(InfluxdbError::Http(format!("Invalid status code: {}", status)))),
        })
    }

    fn log(&self, body: Body) -> impl Future<Item=(), Error=InfluxdbError> {
        // Build response future
        let uri: Uri = format!("{}/write?db={}", &self.connection_string, &self.db).parse().unwrap();
        let response_future = self.client
            .request(
                Request::post(uri)
                    .header(AUTHORIZATION, &*self.authorization)
                    .body(body)
                    .unwrap()
            )
            .map_err(|e| InfluxdbError::Http(format!("Request failed: {}", e)));

        // Handle response status codes
        response_future.and_then(|response: Response<Body>| match response.status() {
            StatusCode::NO_CONTENT => Ok(()),
            StatusCode::NOT_FOUND => Err(InfluxdbError::DatabaseNotFound),
            status => Err(InfluxdbError::Http(format!("Invalid status code: {}", status))),
        })
    }

    /// Log the starting of the push relay server.
    pub fn log_started(&self) -> impl Future<Item=(), Error=InfluxdbError> {
        debug!("Logging \"started\" event to InfluxDB");
        self.log(format!("started,host={} value=1", self.hostname).into())
    }

    /// Log a push (either successful or failed) to InfluxDB.
    pub fn log_push(
        &self,
        push_type: &str,
        version: u16,
        success: bool,
    ) -> impl Future<Item=(), Error=InfluxdbError> {
        debug!(
            "Logging \"push\" event ({}, {}, v{}) to InfluxDB",
            if success { "successful" } else { "failed" },
            push_type,
            version,
        );
        let success_str = if success { "t" } else { "f" };
        self.log(format!(
            "push,host={},type={},version={} success={}",
            self.hostname,
            push_type.to_ascii_lowercase(),
            version,
            success_str,
        ).into())
    }
}
