use axum::{
    http::HeaderMap,
    response::{sse::Event, IntoResponse, Sse},
    Json,
};
use axum_extra::extract::CookieJar;
use eventsource_stream::{EventStream, Eventsource};
use futures::StreamExt;
use futures_core::Stream;
use reqwest::StatusCode;
use serde_json::Value;
use std::{convert::Infallible, str::FromStr};

use crate::{
    arkose::{ArkoseToken, GPT4Model, Type},
    chatgpt::model::{
        req::{Content, Messages, PostConvoRequest},
        resp::{ConvoResponse, PostConvoResponse},
    },
    context,
    serve::{err::ResponseError, has_puid, header_convert},
};
use crate::{chatgpt::model::Role, debug};

use crate::{
    chatgpt::model::{
        req::{Action, ContentText},
        Author,
    },
    uuid::uuid,
};

use crate::URL_CHATGPT_API;

mod req;
mod resp;

pub(crate) async fn chat_to_api(
    headers: HeaderMap,
    jar: CookieJar,
    body: Json<req::Req>,
) -> Result<impl IntoResponse, ResponseError> {
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
            .build();
        messages.push(message)
    }

    let model_mapper = model_mapper(&body.model).await?;
    let parent_message_id = uuid();
    let req = PostConvoRequest::builder()
        .action(Action::Next)
        .parent_message_id(&parent_message_id)
        .messages(messages)
        .model(model_mapper.0)
        .history_and_training_disabled(true)
        .arkose_token(model_mapper.2.as_ref())
        .build();

    let client = context::get_instance().client();
    let new_headers = header_convert(&headers, &jar).await?;
    if GPT4Model::from_str(model_mapper.0).is_ok() {
        if !has_puid(&new_headers)? {
            let result = client
                .get(format!("{URL_CHATGPT_API}/backend-api/models"))
                .headers(new_headers.clone())
                .send()
                .await;

            result
                .map_err(ResponseError::InternalServerError)?
                .error_for_status()
                .map_err(ResponseError::BadRequest)?;
        }
    }

    let resp = client
        .post(format!("{URL_CHATGPT_API}/backend-api/conversation"))
        .headers(new_headers)
        .json(&req)
        .send()
        .await
        .map_err(ResponseError::InternalServerError)?;

    match resp.error_for_status() {
        Ok(resp) => {
            let event_source = resp.bytes_stream().eventsource();
            match body.stream {
                true => Ok(
                    Sse::new(stream_handler(event_source, model_mapper.1.to_owned()))
                        .into_response(),
                ),
                false => {
                    let res = not_stream_handler(event_source, model_mapper.1.to_owned())
                        .await
                        .map_err(ResponseError::InternalServerError)?;
                    Ok(res.into_response())
                }
            }
        }
        Err(err) => match err.status() {
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
                        let body = serde_json::json!({
                            "error": {
                                "message": "You didn't provide an API key. You need to provide your API key in an Authorization header using Bearer auth (i.e. Authorization: Bearer YOUR_KEY), or as the password field (with blank username) if you're accessing the API from your browser and are prompted for a username and password. You can obtain an API key from https://platform.openai.com/account/api-keys.",
                                "type": "invalid_request_error",
                                "param": null,
                                "code": null
                            }
                        });
                        return Ok(Json(body).into_response().into_response())
                    }
                    Err(ResponseError::new(err.to_string(), status_code))
                },
                _ => Err(ResponseError::InternalServerError(err)),
            },
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

    let message = resp::Message::builder()
        .role(Role::Assistant.to_string())
        .content(previous_message)
        .build();

    let resp = resp::Resp::builder()
        .id(&id)
        .object("chat.completion.chunk")
        .created(&timestamp)
        .model(&model)
        .choices(vec![resp::Choice::builder()
            .index(0)
            .message(Some(message))
            .finish_reason(finish_reason.as_deref())
            .build()])
        .usage(Some(
            resp::Usage::builder()
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
    let messages = convo.messages();
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

    let delta = resp::Delta::builder()
        .role(role)
        .content(return_message)
        .build();

    let resp = resp::Resp::builder()
        .id(&id)
        .object("chat.completion.chunk")
        .created(timestamp)
        .model(&model)
        .choices(vec![resp::Choice::builder()
            .index(0)
            .delta(Some(delta))
            .finish_reason(finish_reason)
            .build()])
        .build();
    let data = format!(" {}", serde_json::to_string(&resp)?);
    Ok(Event::default().data(data))
}

async fn model_mapper(model: &str) -> Result<(&str, &str, Option<ArkoseToken>), ResponseError> {
    match model {
        model if model.starts_with("gpt-3.5") => {
            Ok(("text-davinci-002-render-sha", "gpt-3.5-turbo", None))
        }
        model if model.starts_with("gpt-4") => Ok((
            "gpt-4",
            "gpt-4",
            Some(ArkoseToken::new_from_context(Type::Chat).await?),
        )),
        _ => Err(ResponseError::BadRequest(anyhow::anyhow!(
            "not support model: {model}"
        ))),
    }
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
