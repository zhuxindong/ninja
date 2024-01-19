use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;
pub mod req;
pub mod resp;

/// A role of a message sender, can be:
/// - `System`, for starting system message, that sets the tone of model
/// - `Assistant`, for messages sent by ChatGPT
/// - `User`, for messages sent by user
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// A system message, automatically sent at the start to set the tone of the model
    System,
    /// A message sent by ChatGPT
    Assistant,
    /// A message sent by the user
    User,
    /// A system message
    Critic,
}

impl ToString for Role {
    fn to_string(&self) -> String {
        match self {
            Role::System => "system".to_string(),
            Role::Assistant => "assistant".to_string(),
            Role::User => "user".to_string(),
            Role::Critic => "critic".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, TypedBuilder, Debug)]
pub struct Author {
    pub role: Role,
}
