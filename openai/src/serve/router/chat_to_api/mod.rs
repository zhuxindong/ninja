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
use std::convert::Infallible;

use crate::{
    arkose::ArkoseToken,
    chatgpt::model::resp::{ConvoResponse, PostConvoResponse},
    serve::{api_client, err::ResponseError, header_convert, ARKOSE_TOKEN_ENDPOINT},
};
use crate::{chatgpt::model::Role, debug};

use crate::{
    chatgpt::model::{
        req::{Action, ContentBuilder, ContentText, MessagesBuilder, PostConvoRequestBuilder},
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
    let mut messages = vec![];
    for body_msg in body.messages.iter() {
        let role = if body_msg.role.eq(&Role::System) {
            Role::Critic
        } else {
            body_msg.role
        };
        let message = MessagesBuilder::default()
            .id(uuid())
            .author(Author { role })
            .content(
                ContentBuilder::default()
                    .content_type(ContentText::Text)
                    .parts(vec![&body_msg.content])
                    .build()
                    .map_err(|err| ResponseError::InternalServerError(err))?,
            )
            .build()
            .map_err(|err| ResponseError::InternalServerError(err))?;
        messages.push(message)
    }

    let conv_model = conv_model(&body.model).await?;
    let parent_message_id = uuid();
    let req = PostConvoRequestBuilder::default()
        .action(Action::Next)
        .parent_message_id(&parent_message_id)
        .messages(messages)
        .model(conv_model.0)
        .history_and_training_disabled(true)
        .build()
        .map_err(|err| ResponseError::InternalServerError(err))?;

    let client = api_client();
    let resp = client
        .post(format!("{URL_CHATGPT_API}/backend-api/conversation"))
        .headers(header_convert(headers, jar).await)
        .json(&req)
        .send()
        .await
        .map_err(|err| ResponseError::InternalServerError(err))?;

    match resp.error_for_status() {
        Ok(resp) => {
            let event_source = resp.bytes_stream().eventsource();
            if body.stream {
                Ok(Sse::new(stream_handler(event_source, conv_model.0.to_owned())).into_response())
            } else {
                Ok(not_stream_handler(event_source, conv_model.0.to_owned())
                    .await?
                    .into_response())
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
) -> Result<Json<Value>, ResponseError> {
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
                        if let Some(true) = convo.end_turn().filter(|&end| end) {
                            previous_message = convo.messages()[0].to_string();
                            finish_reason = Some(convo.metadata_finish_details_type());
                            break;
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

    let message = resp::MessageBuilder::default()
        .role(Role::Assistant.to_string())
        .content(previous_message)
        .build()
        .unwrap();

    let resp = resp::RespBuilder::default()
        .id(&id)
        .object("chat.completion.chunk")
        .created(timestamp)
        .model(&model)
        .choices(vec![resp::ChoiceBuilder::default()
            .index(0)
            .message(Some(message))
            .finish_reason(finish_reason)
            .build()
            .unwrap()])
        .usage(Some(
            resp::UsageBuilder::default()
                .prompt_tokens(0)
                .completion_tokens(0)
                .total_tokens(0)
                .build()
                .unwrap(),
        ))
        .build()
        .unwrap();
    let value =
        serde_json::to_value(&resp).map_err(|err| ResponseError::InternalServerError(err))?;
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

                            match event_convert_handler(&id, timestamp, &model, &mut previous_message, &mut set_role, convo).await {
                                Ok(event) => {
                                    yield Ok(event)
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
    id: &String,
    timestamp: i64,
    model: &String,
    previous_message: &mut String,
    set_role: &mut bool,
    convo: ConvoResponse,
) -> Result<Event, serde_json::Error> {
    let message = &convo.messages()[0];

    let finish_reason = convo
        .end_turn()
        .filter(|&end| end)
        .map(|_| convo.metadata_finish_details_type());

    let role: Option<String> = if *set_role {
        *set_role = false;
        Some(convo.role().to_string())
    } else {
        None
    };

    let return_message = message.replace(&*previous_message, "");
    *previous_message = message.to_string();

    let delta = resp::DeltaBuilder::default()
        .role(role)
        .content(Some(return_message))
        .build()
        .unwrap();

    let resp = resp::RespBuilder::default()
        .id(&id)
        .object("chat.completion.chunk")
        .created(timestamp)
        .model(&model)
        .choices(vec![resp::ChoiceBuilder::default()
            .index(0)
            .delta(Some(delta))
            .finish_reason(finish_reason)
            .build()
            .unwrap()])
        .build()
        .unwrap();
    Event::default().json_data(resp)
}

async fn conv_model(model: &str) -> Result<(&str, Option<ArkoseToken>), ResponseError> {
    match model {
        "gpt-3.5" => Ok(("text-davinci-002-render-sha", None)),
        model if model.starts_with("gpt-4") => {
            if let Some(endpoint) = unsafe { ARKOSE_TOKEN_ENDPOINT.as_ref() } {
                if let Ok(arkose_token) = ArkoseToken::new_from_endpoint(model, endpoint).await {
                    return Ok(("gpt-4", Some(arkose_token)));
                }
            }
            Ok(("gpt-4", None))
        }
        _ => Ok(("text-davinci-002-render-sha", None)),
    }
}

fn generate_id(length: usize) -> String {
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let rng = thread_rng();
    "chatcmpl-".to_string()
        + &rng
            .sample_iter(Alphanumeric)
            .take(length)
            .map(|c| CHARSET[c as usize % CHARSET.len()] as char)
            .collect::<String>()
}

fn current_timestamp() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let current_time = SystemTime::now();
    let since_epoch = current_time
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_epoch.as_secs() as i64
}
