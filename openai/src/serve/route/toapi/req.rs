use serde::Deserialize;

use crate::chatgpt::model::Role;

#[derive(Deserialize)]
pub struct Req {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(default)]
    pub stream: bool,
}

#[derive(Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: String,
}
