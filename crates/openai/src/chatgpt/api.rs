#[cfg(feature = "stream")]
use crate::eventsource::{Event, EventSource, RequestBuilderExt};
#[cfg(feature = "stream")]
use futures::{stream::StreamExt, Stream};
use std::pin::Pin;

pub type ApiResult<T, E = ApiError> = anyhow::Result<T, E>;

pub enum RequestMethod {
    GET,
    POST,
    PATCH,
    PUT,
    DELETE,
}

#[derive(thiserror::Error, Debug)]
pub enum ApiError {
    #[error("failed to cookie")]
    FailedGetCookieError,
    #[error("invalid cookie")]
    InvalidCookieError,
    #[error(transparent)]
    SerdeDeserializeError(#[from] serde_json::error::Error),
    #[error(transparent)]
    JsonReqwestDeserializeError(#[from] reqwest::Error),
    #[error(transparent)]
    JsonAnyhowDeserializeError(#[from] anyhow::Error),
    #[error("failed serialize `{0}`")]
    SerializeError(String),
    #[error("stream error `{0}`")]
    StreamError(String),
    #[error("system time exception")]
    SystemTimeExceptionError,
    #[error("too many requests `{0}`")]
    TooManyRequestsError(String),
    #[error("failed authentication `{0}`")]
    BadAuthenticationError(String),
    #[error("failed request `{0}`")]
    FailedRequestError(String),
    #[error("redirection error")]
    RedirectionError,
    #[error("bad request `{0}`")]
    BadRequestError(String),
    #[error("server error")]
    ServerError,
    #[error("format prefix string error")]
    FormatPrefixStringError,
    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    #[error("required parameter `{0}`")]
    RequiredParameter(String),
}

use reqwest::{impersonate::Impersonate, Proxy, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;
use tokio::sync::RwLock;

use super::model::{req, resp};
use crate::URL_CHATGPT_API;

pub struct ChatGPT {
    api_prefix: String,
    client: reqwest::Client,
    access_token: RwLock<String>,
}

impl ChatGPT {
    async fn request<U>(&self, url: String, method: RequestMethod) -> ApiResult<U>
    where
        U: DeserializeOwned,
    {
        let token = self.access_token.read().await;
        let resp = match method {
            RequestMethod::GET => self.client.get(&url),
            RequestMethod::POST => self.client.post(&url),
            RequestMethod::PATCH => self.client.patch(&url),
            RequestMethod::PUT => self.client.put(&url),
            RequestMethod::DELETE => self.client.delete(&url),
        }
        .bearer_auth(token)
        .send()
        .await?;
        self.response_handle(resp).await
    }

    async fn request_payload<T, U>(
        &self,
        url: String,
        method: RequestMethod,
        payload: &T,
    ) -> ApiResult<U>
    where
        T: Serialize + ?Sized,
        U: DeserializeOwned,
    {
        let token = self.access_token.read().await;
        let resp = match method {
            RequestMethod::POST => self.client.post(&url),
            RequestMethod::PATCH => self.client.patch(&url),
            RequestMethod::PUT => self.client.put(&url),
            RequestMethod::DELETE => self.client.delete(&url),
            _ => {
                return Err(ApiError::FailedRequestError(
                    "not supported method".to_owned(),
                ))
            }
        }
        .bearer_auth(token)
        .json(payload)
        .send()
        .await?;
        self.response_handle::<U>(resp).await
    }

    async fn response_handle<U: DeserializeOwned>(&self, resp: reqwest::Response) -> ApiResult<U> {
        match resp.error_for_status_ref() {
            Ok(_) => Ok(resp
                .json::<U>()
                .await
                .map_err(ApiError::JsonReqwestDeserializeError)?),
            Err(err) => Err(self.err_handle(err, resp).await?),
        }
    }

    async fn err_handle(
        &self,
        err: reqwest::Error,
        resp: reqwest::Response,
    ) -> ApiResult<ApiError> {
        let url = resp.url().clone();
        let err_msg = format!("error: {}, url: {}", resp.text().await?, url);
        match err.status() {
                Some(
                    status_code
                    @
                    // 4xx
                    (StatusCode::UNAUTHORIZED
                    | StatusCode::REQUEST_TIMEOUT
                    | StatusCode::TOO_MANY_REQUESTS
                    | StatusCode::BAD_REQUEST
                    | StatusCode::PAYMENT_REQUIRED
                    | StatusCode::FORBIDDEN
                    // 5xx
                    | StatusCode::INTERNAL_SERVER_ERROR
                    | StatusCode::BAD_GATEWAY
                    | StatusCode::SERVICE_UNAVAILABLE
                    | StatusCode::GATEWAY_TIMEOUT),
                ) => {
                    if status_code == StatusCode::UNAUTHORIZED {
                        return Ok(ApiError::BadAuthenticationError(err_msg))
                    }
                    if status_code == StatusCode::TOO_MANY_REQUESTS {
                        return Ok(ApiError::TooManyRequestsError(err_msg))
                    }
                    if status_code.is_client_error() {
                        return Ok(ApiError::BadRequestError(err_msg))
                    }
                    Ok(ApiError::ServerError)
                },
                _ => Ok(ApiError::FailedRequestError(err_msg)),
            }
    }

    #[cfg(feature = "stream")]
    pub async fn process_stream<O>(
        mut event_soure: EventSource,
    ) -> Pin<Box<dyn Stream<Item = Result<O, ApiError>> + Send>>
    where
        O: DeserializeOwned + Send + 'static,
    {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        tokio::spawn(async move {
            while let Some(event_result) = event_soure.next().await {
                match event_result {
                    Ok(event) => match event {
                        Event::Open => continue,
                        Event::Message(message) => {
                            if message.data == "[DONE]" {
                                break;
                            }

                            let response = match serde_json::from_str::<O>(&message.data) {
                                Ok(result) => Ok(result),
                                Err(error) => Err(ApiError::SerdeDeserializeError(error)),
                            };

                            if let Err(_error) = tx.send(response) {
                                break;
                            }
                        }
                    },
                    Err(error) => {
                        if let Err(_error) = tx.send(Err(ApiError::StreamError(error.to_string())))
                        {
                            break;
                        }
                    }
                }
            }

            event_soure.close();
        });

        Box::pin(tokio_stream::wrappers::UnboundedReceiverStream::new(rx))
    }
}

impl ChatGPT {
    pub async fn get_models(&self) -> ApiResult<resp::GetModelsResponse> {
        self.request(format!("{}/models", self.api_prefix), RequestMethod::GET)
            .await
    }

    pub async fn get_account_check(&self) -> ApiResult<resp::GetAccountsCheckResponse> {
        self.request(
            format!("{}/accounts/check", self.api_prefix),
            RequestMethod::GET,
        )
        .await
    }

    pub async fn get_account_check_4(&self) -> ApiResult<resp::GetAccountsCheckV4Response> {
        self.request(
            format!("{}/accounts/check/v4-2023-04-27", self.api_prefix),
            RequestMethod::GET,
        )
        .await
    }

    pub async fn get_conversation<'a>(
        &self,
        req: req::GetConvoRequest<'a>,
    ) -> ApiResult<resp::GetConvoResponse> {
        match req.conversation_id {
            Some(conversation_id) => {
                self.request::<resp::GetConvoResponse>(
                    format!("{}/conversation/{conversation_id}", self.api_prefix),
                    RequestMethod::GET,
                )
                .await
            }
            None => Err(ApiError::RequiredParameter("conversation_id".to_string())),
        }
    }

    pub async fn get_conversations<'a>(
        &self,
        req: req::GetConvoRequest<'a>,
    ) -> ApiResult<resp::GetConvosResponse> {
        self.request::<resp::GetConvosResponse>(
            format!(
                "{}/conversations?offset={}&limit={}&order=updated",
                self.api_prefix, req.offset, req.limit
            ),
            RequestMethod::GET,
        )
        .await
    }

    #[cfg(feature = "stream")]
    pub async fn post_conversation<'a>(
        &self,
        req: req::PostConvoRequest<'a>,
    ) -> Pin<Box<dyn Stream<Item = ApiResult<resp::PostConvoResponse>> + Send>> {
        let url = format!("{}/conversation", self.api_prefix);
        let resp = self
            .client
            .post(url)
            .bearer_auth(&self.access_token.read().await)
            .json(&req)
            .eventsource()
            .expect("eventsource error");
        Self::process_stream::<resp::PostConvoResponse>(resp).await
    }

    pub async fn post_conversation_completions<'a>(
        &self,
        req: req::PostConvoRequest<'a>,
    ) -> ApiResult<Vec<resp::PostConvoResponse>> {
        let url = format!("{}/conversation", self.api_prefix);
        let resp = self
            .client
            .post(url)
            .bearer_auth(&self.access_token.read().await)
            .json(&req)
            .send()
            .await?;

        match resp.error_for_status_ref() {
            Ok(_) => {
                let mut v = Vec::new();
                let mut stream = resp.bytes_stream();

                while let Some(item) = StreamExt::next(&mut stream).await {
                    let body =
                        String::from_utf8(item?.to_vec()).map_err(ApiError::FromUtf8Error)?;

                    if body.starts_with("data: {") {
                        let chunks: Vec<&str> = body.lines().filter(|s| !s.is_empty()).collect();
                        for ele in chunks {
                            let body = ele.trim_start_matches("data: ").trim();
                            let res = serde_json::from_str::<resp::PostConvoResponse>(body)
                                .map_err(ApiError::SerdeDeserializeError)?;
                            v.push(res);
                        }
                    } else if body.starts_with("data: [DONE]")
                        || body.starts_with("data: { \"conversation_id\"")
                    {
                        break;
                    }
                }

                Ok(v)
            }
            Err(err) => Err(self.err_handle(err, resp).await?),
        }
    }

    pub async fn patch_conversation<'a>(
        &self,
        req: req::PatchConvoRequest<'a>,
    ) -> ApiResult<resp::PatchConvoResponse> {
        match &req.conversation_id {
            Some(conversation_id) => {
                self.request_payload(
                    format!("{}/conversation/{conversation_id}", self.api_prefix),
                    RequestMethod::PATCH,
                    &req,
                )
                .await
            }
            None => Err(ApiError::RequiredParameter("conversation_id".to_string())),
        }
    }

    pub async fn patch_conversations<'a>(
        &self,
        req: req::PatchConvoRequest<'a>,
    ) -> ApiResult<resp::PatchConvoResponse> {
        self.request_payload(
            format!("{}/conversations", self.api_prefix),
            RequestMethod::PATCH,
            &req,
        )
        .await
    }

    pub async fn post_conversation_gen_title<'a>(
        &self,
        req: req::PostConvoGenTitleRequest<'a>,
    ) -> ApiResult<resp::PostConvoGenTitleResponse> {
        self.request_payload(
            format!(
                "{}/conversation/gen_title/{}",
                self.api_prefix, req.conversation_id,
            ),
            RequestMethod::POST,
            &req,
        )
        .await
    }

    pub async fn message_feedback<'a>(
        &self,
        req: req::MessageFeedbackRequest<'a>,
    ) -> ApiResult<resp::MessageFeedbackResponse> {
        self.request_payload(
            format!("{}/conversation/message_feedback", self.api_prefix),
            RequestMethod::POST,
            &req,
        )
        .await
    }

    pub async fn get_conversation_limit(&self) -> ApiResult<resp::GetConvoLimitResponse> {
        self.request(
            format!("{URL_CHATGPT_API}/public-api/conversation_limit"),
            RequestMethod::GET,
        )
        .await
    }
}

pub struct ChatGPTBuilder {
    builder: reqwest::ClientBuilder,
    api_prefix: String,
    access_token: RwLock<String>,
}

impl ChatGPTBuilder {
    pub fn access_token(mut self, access_token: String) -> Self {
        self.access_token = RwLock::new(access_token);
        self
    }

    pub fn api_prefix(mut self, url: String) -> Self {
        self.api_prefix = url;
        self
    }

    pub fn proxy(mut self, proxy: Proxy) -> Self {
        self.builder = self.builder.proxy(proxy);
        self
    }

    pub fn no_proxy(mut self) -> Self {
        self.builder = self.builder.no_proxy();
        self
    }

    pub fn client_timeout(mut self, timeout: Duration) -> Self {
        self.builder = self.builder.timeout(timeout);
        self
    }

    pub fn client_connect_timeout(mut self, timeout: Duration) -> Self {
        self.builder = self.builder.connect_timeout(timeout);
        self
    }

    pub fn cookie_store(mut self, store: bool) -> Self {
        self.builder = self.builder.cookie_store(store);
        self
    }

    /// Sets the necessary values to mimic the specified Chrome version.
    pub fn impersonate(mut self, ver: Impersonate) -> Self {
        self.builder = self.builder.impersonate(ver);
        self
    }

    /// Sets the `User-Agent` header to be used by this client.
    pub fn user_agent(mut self, value: &str) -> Self {
        self.builder = self.builder.user_agent(value);
        self
    }

    pub fn build(self) -> ChatGPT {
        ChatGPT {
            api_prefix: self.api_prefix,
            client: self.builder.build().expect("ClientBuilder::build()"),
            access_token: self.access_token,
        }
    }

    pub fn builder() -> ChatGPTBuilder {
        let builder = reqwest::ClientBuilder::new()
            .impersonate(Impersonate::OkHttp4_9)
            .permute_extensions(true)
            .enable_ech_grease(true)
            .danger_accept_invalid_certs(true)
            .cookie_store(true);

        ChatGPTBuilder {
            builder,
            api_prefix: format!("{URL_CHATGPT_API}/backend-api"),
            access_token: RwLock::default(),
        }
    }
}
