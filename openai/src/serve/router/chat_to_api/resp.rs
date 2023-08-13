use derive_builder::Builder;
use serde::Serialize;

#[derive(Serialize, Builder, Clone)]
pub struct Resp<'a> {
    id: &'a str,
    object: &'a str,
    created: i64,
    model: &'a str,
    choices: Vec<Choice>,
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<Usage>,
}

#[derive(Serialize, Builder, Clone)]
pub struct Usage {
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
}

#[derive(Serialize, Builder, Clone)]
pub struct Choice {
    pub index: i64,
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<Delta>,
    #[builder(default)]
    pub finish_reason: Option<String>,
}

#[derive(Serialize, Builder, Clone)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Serialize, Builder, Clone)]
pub struct Delta {
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}
