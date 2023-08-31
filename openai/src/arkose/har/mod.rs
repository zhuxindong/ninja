#[allow(dead_code)]
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Har {
    pub entries: Vec<Entries>,
}

#[derive(Debug, Deserialize)]
pub struct Entries {
    #[serde(rename = "request")]
    pub request: Request,
    #[serde(rename = "startedDateTime")]
    pub started_date_time: String,
}

#[derive(Debug, Deserialize)]
pub struct Request {
    pub method: String,
    pub url: String,
    #[serde(rename = "httpVersion")]
    pub http_version: String,
    pub headers: Vec<Header>,
    #[serde(rename = "queryString")]
    pub query_string: Vec<QueryString>,
    pub cookies: Vec<Cookie>,
    #[serde(rename = "headersSize")]
    pub headers_size: i32,
    #[serde(rename = "bodySize")]
    pub body_size: i32,
    #[serde(rename = "postData")]
    pub post_data: Option<PostData>,
}

#[derive(Debug, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct QueryString {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct PostData {
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    pub text: String,
    pub params: Vec<Param>,
}

#[derive(Debug, Deserialize)]
pub struct Param {
    pub name: String,
    pub value: String,
}
