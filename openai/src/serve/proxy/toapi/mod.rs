mod model;

use axum::http::header;
use axum::http::Method;
use axum::{
    response::{sse::Event, IntoResponse, Sse},
    Json,
};
use eventsource_stream::{EventStream, Eventsource};
use futures::StreamExt;
use futures_core::Stream;
use reqwest::StatusCode;
use serde_json::Value;
use std::{convert::Infallible, str::FromStr};

use crate::chatgpt::model::req::Metadata;
use crate::serve::error::ProxyError;
use crate::{
    arkose::{ArkoseToken, GPTModel},
    chatgpt::model::{
        req::{Content, ConversationMode, Messages, PostConvoRequest},
        resp::{ConvoResponse, PostConvoResponse},
    },
    serve::{
        error::ResponseError,
        puid::{get_or_init, reduce_key},
    },
    with_context,
};
use crate::{chatgpt::model::Role, debug};
use crate::{
    chatgpt::model::{
        req::{Action, ContentText},
        Author,
    },
    uuid::uuid,
};

use super::ext::{ContextExt, RequestExt, ResponseExt};
use crate::URL_CHATGPT_API;

/// Check if the request is supported
pub(super) fn support(req: &RequestExt) -> bool {
    if req.uri.path().eq("/v1/chat/completions") && req.method.eq(&Method::POST) {
        if let Some(ref b) = req.bearer_auth() {
            return !b.starts_with("sk-");
        }
    }
    false
}

/// Send request to ChatGPT API
pub(super) async fn send_request(req: RequestExt) -> Result<ResponseExt, ResponseError> {
    // Exstract the token from the Authorization header
    let baerer = req
        .bearer_auth()
        .ok_or(ResponseError::BadRequest(ProxyError::AccessTokenRequired))?;

    // Exstract the token from the Authorization header
    let cache_id = reduce_key(baerer)?;

    // Exstract the body
    let bytes = req
        .body
        .as_ref()
        .ok_or_else(|| ResponseError::BadRequest(ProxyError::BodyRequired))?;
    let body = serde_json::from_slice::<model::Req>(bytes)?;

    // Convert to ChatGPT API Message
    let mut messages = Vec::with_capacity(body.messages.len());
    for body_msg in body.messages.iter() {
        let role = if body_msg.role.eq(&Role::System) {
            Role::Critic
        } else {
            body_msg.role
        };
        let message = Messages::builder()
            .id(uuid())
            .author(Author { role })
            .content(
                Content::builder()
                    .content_type(ContentText::Text)
                    .parts(vec![&body_msg.content])
                    .build(),
            )
            .metadata(Metadata {})
            .build();
        messages.push(message)
    }

    // OpenAI API to ChatGPT API model mapper
    let (raw_model, mapper_model, arkose_token) = model_mapper(&body.model).await?;

    // Create request
    let parent_message_id = uuid();
    let req_body = PostConvoRequest::builder()
        .action(Action::Next)
        .parent_message_id(&parent_message_id)
        .messages(messages)
        .model(raw_model)
        .history_and_training_disabled(true)
        .force_paragen(false)
        .force_rate_limit(false)
        .conversation_mode(ConversationMode {
            kind: "primary_assistant",
        })
        .arkose_token(&arkose_token)
        .build();

    let mut builder = with_context!(client)
        .post(format!("{URL_CHATGPT_API}/backend-api/conversation"))
        .header(header::ORIGIN, URL_CHATGPT_API)
        .header(header::REFERER, URL_CHATGPT_API)
        .bearer_auth(baerer);

    // Try to get puid from cache
    let puid = get_or_init(baerer, &body.model, cache_id).await?;
    if let Some(puid) = puid {
        builder = builder.header(header::COOKIE, format!("_puid={puid};"))
    }

    // Send request
    let resp = builder
        .json(&req_body)
        .send()
        .await
        .map_err(ResponseError::InternalServerError)?;
    Ok(ResponseExt::builder()
        .inner(resp)
        .context(
            ContextExt::builder()
                .model(mapper_model.to_owned())
                .stream(body.stream)
                .build(),
        )
        .build())
}

/// Convert response to ChatGPT API
pub(super) async fn response_convert(
    resp_ext: ResponseExt,
) -> Result<impl IntoResponse, ResponseError> {
    match resp_ext.inner.error_for_status() {
        Ok(resp) => {
            let config =
                resp_ext
                    .context
                    .ok_or(ResponseError::InternalServerError(anyhow::anyhow!(
                        "to_api is empty"
                    )))?;
            let event_source = resp.bytes_stream().eventsource();
            if config.stream {
                return Ok(Sse::new(stream_handler(event_source, config.model)).into_response());
            } else {
                let res = not_stream_handler(event_source, config.model)
                    .await
                    .map_err(ResponseError::InternalServerError)?;
                return Ok(res.into_response());
            }
        }
        Err(err) => {
            if let Some(status_code) = err.status() {
                match status_code {
                    StatusCode::UNAUTHORIZED => {
                        let body = serde_json::json!({
                            "error": {
                                "message": "You didn't provide an API key. You need to provide your API key in an Authorization header using Bearer auth (i.e. Authorization: Bearer YOUR_KEY), or as the password field (with blank username) if you're accessing the API from your browser and are prompted for a username and password. You can obtain an API key from https://platform.openai.com/account/api-keys.",
                                "type": "invalid_request_error",
                                "param": null,
                                "code": null
                            }
                        });
                        return Ok(Json(body).into_response());
                    }
                    _ => {
                        return Err(ResponseError::new(err.to_string(), status_code));
                    }
                }
            } else {
                return Err(ResponseError::InternalServerError(err));
            }
        }
    }
}

async fn not_stream_handler(
    mut event_soure: EventStream<
        impl Stream<Item = Result<bytes::Bytes, reqwest::Error>> + std::marker::Unpin,
    >,
    model: String,
) -> anyhow::Result<Json<Value>> {
    let id = generate_id(29);
    let timestamp = current_timestamp();
    let mut previous_message = String::new();
    let mut finish_reason = None;
    while let Some(event_result) = event_soure.next().await {
        match event_result {
            Ok(message) => {
                if message.data.eq("[DONE]") {
                    break;
                }
                if let Ok(res) = serde_json::from_str::<PostConvoResponse>(&message.data) {
                    if let PostConvoResponse::Conversation(convo) = res {
                        let finish = convo.metadata_finish_details_type();
                        if !finish.is_empty() {
                            finish_reason = Some(finish.to_owned())
                        }
                        let messages = convo.messages();
                        if let Some(message) = messages.first() {
                            previous_message.clear();
                            previous_message.push_str(message);
                        }
                    }
                }
            }
            Err(err) => {
                debug!("event-source stream error: {}", err);
            }
        }
    }
    drop(event_soure);

    let message = model::Message::builder()
        .role(Role::Assistant)
        .content(previous_message)
        .build();

    let resp = model::Resp::builder()
        .id(&id)
        .object("chat.completion.chunk")
        .created(&timestamp)
        .model(&model)
        .choices(vec![model::Choice::builder()
            .index(0)
            .message(Some(message))
            .finish_reason(finish_reason.as_deref())
            .build()])
        .usage(Some(
            model::Usage::builder()
                .prompt_tokens(0)
                .completion_tokens(0)
                .total_tokens(0)
                .build(),
        ))
        .build();
    let value = serde_json::to_value(&resp)?;
    Ok(Json(value))
}

fn stream_handler(
    mut event_soure: EventStream<
        impl Stream<Item = Result<bytes::Bytes, reqwest::Error>> + std::marker::Unpin,
    >,
    model: String,
) -> impl Stream<Item = Result<Event, Infallible>> {
    let id = generate_id(29);
    let timestamp = current_timestamp();
    async_stream::stream! {
        let mut previous_message = String::new();
        let mut set_role = true;
        let mut stop: u8 = 0;
        while let Some(event_result) = event_soure.next().await {
            match event_result {
                Ok(message) =>  {
                    if message.data.eq("[DONE]") {
                        yield Ok(Event::default().data(message.data));
                        break;
                    }
                    if let Ok(res) = serde_json::from_str::<PostConvoResponse>(&message.data) {
                        if let PostConvoResponse::Conversation(convo) = res {

                            if (convo.role().ne(&Role::Assistant) || convo.messages().is_empty())
                                || (convo.metadata_message_type().ne("next") && convo.metadata_message_type().ne("continue")) {
                                continue;
                            }

                            match event_convert_handler(
                                &mut stop,
                                &id,
                                &timestamp,
                                &model,
                                &mut previous_message,
                                &mut set_role,
                                convo).await {
                                Ok(event) => {
                                    if stop == 0 {
                                        yield Ok(event)
                                    } else if stop <= 1 {
                                        yield Ok(event)
                                    }
                                },
                                Err(err) => {
                                    debug!("event source json serialize error: {}", err);
                                }
                            }
                        }
                    }
                },
                Err(err) => {
                    debug!("event-source stream error: {}", err);
                }
            }
        }
    }
}

async fn event_convert_handler(
    stop: &mut u8,
    id: &String,
    timestamp: &i64,
    model: &String,
    previous_message: &mut String,
    set_role: &mut bool,
    convo: ConvoResponse,
) -> anyhow::Result<Event> {
    let messages = convo.raw_messages();
    let message = messages
        .first()
        .ok_or(anyhow::anyhow!("message is empty"))?;

    let finish_reason = convo
        .end_turn()
        .filter(|&end| end)
        .map(|_| convo.metadata_finish_details_type());

    let role = if *set_role {
        *set_role = false;
        Some(convo.role())
    } else {
        None
    };

    let return_message = if finish_reason.is_some_and(|finish| finish.eq("stop")) {
        *stop += 1;
        None
    } else {
        Some(message.trim_start_matches(previous_message.as_str()))
    };

    previous_message.clear();
    previous_message.push_str(message);

    let delta = model::Delta::builder()
        .role(role)
        .content(return_message)
        .build();

    let resp = model::Resp::builder()
        .id(&id)
        .object("chat.completion.chunk")
        .created(timestamp)
        .model(&model)
        .choices(vec![model::Choice::builder()
            .index(0)
            .delta(Some(delta))
            .finish_reason(finish_reason)
            .build()])
        .build();
    let data = format!(" {}", serde_json::to_string(&resp)?);
    Ok(Event::default().data(data))
}

async fn model_mapper(model: &str) -> Result<(&str, &str, Option<ArkoseToken>), ResponseError> {
    let gpt_model = GPTModel::from_str(model)?;

    let arkose_token =
        if (with_context!(arkose_gpt3_experiment) && gpt_model.is_gpt3()) || gpt_model.is_gpt4() {
            let arkose_token = ArkoseToken::new_from_context(gpt_model.clone().into()).await?;
            Some(arkose_token)
        } else {
            None
        };

    if gpt_model.is_gpt3() {
        return Ok(("text-davinci-002-render-sha", "gpt-3.5-turbo", arkose_token));
    }

    if gpt_model.is_gpt4() {
        return Ok(("gpt-4", "gpt-4", arkose_token));
    }

    return Err(ResponseError::BadRequest(anyhow::anyhow!(
        "not support model: {model}"
    )));
}

fn generate_id(length: usize) -> String {
    let rand_str = crate::generate_random_string(length);
    format!("chatcmpl-{rand_str}")
}

fn current_timestamp() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let current_time = SystemTime::now();
    let since_epoch = current_time
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_epoch.as_secs() as i64
}
