pub mod chat_completion;
#[cfg(feature = "stream")]
pub mod chat_completion_stream;
pub mod completion;
#[cfg(feature = "stream")]
pub mod completion_stream;
pub mod model;
pub mod shared;
