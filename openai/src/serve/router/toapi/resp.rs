use derive_builder::Builder;
use serde::Serialize;

use crate::chatgpt::model::Role;

#[derive(Serialize, Builder, Clone)]
pub struct Resp<'a> {
    id: &'a str,
    object: &'a str,
    created: &'a i64,
    model: &'a str,
    choices: Vec<Choice<'a>>,
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
pub struct Choice<'a> {
    pub index: i64,
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<Delta<'a>>,
    #[builder(default)]
    pub finish_reason: Option<&'a str>,
}

#[derive(Serialize, Builder, Clone)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Serialize, Builder, Clone)]
pub struct Delta<'a> {
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<&'a Role>,
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<&'a str>,
}
