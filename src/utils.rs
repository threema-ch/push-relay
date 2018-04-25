use futures::future::Future;


/// A type alias for a boxed Future + Send.
pub type SendFuture<T, E> = Box<Future<Item = T, Error = E> + Send>;

/// Wrap Future + Send in a box with type erasure.
macro_rules! sboxed {
    ($future:expr) => {{
        Box::new($future) as SendFuture<_, _>
    }};
}
