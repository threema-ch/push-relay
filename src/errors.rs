use apns2::error::Error as Apns2Error;
use hyper::error::Error as HyperError;

quick_error! {
    #[derive(Debug)]
    pub enum PushError {
        ApnsError(err: Apns2Error) {
            from()
            display("APNs error: {}", err)
            cause(err)
        }
        HyperError(err: HyperError) {
            from()
            display("Hyper error: {}", err)
            cause(err)
        }
        SendError(err: HyperError) {
            display("Push message could not be sent: {}", err)
            cause(err)
        }
        ProcessingError(msg: String) {
            display("Push message could not be processed: {}", msg)
        }
        Other(msg: String) {
            display("Other: {}", msg)
        }
    }
}
