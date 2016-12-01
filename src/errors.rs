use hyper::error::Error as HyperError;

quick_error! {
    #[derive(Debug)]
    pub enum PushError {
        SendError(err: HyperError) {
            from()
            display("GCM message could not be sent: {}", err)
            cause(err)
        }
        ProcessingError(msg: String) {
            display("GCM message could not be processed: {}", msg)
        }
        Other(msg: String) {
            display("Other: {}", msg)
        }
    }
}
