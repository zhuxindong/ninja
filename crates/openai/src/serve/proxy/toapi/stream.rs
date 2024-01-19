use axum::response::sse::Event;
use axum::Json;
use eventsource_stream::EventStream;
use futures_core::Stream;
use serde_json::Value;
use std::convert::Infallible;
use tokio_stream::StreamExt;

use crate::chatgpt::model::resp::{ConvoResponse, PostConvoResponse};
use crate::chatgpt::model::Role;
use crate::serve::error::{ProxyError, ResponseError};
use crate::serve::ProxyResult;
use crate::warn;

use super::model;

struct HandlerContext<'a> {
    stop: &'a mut u8,
    id: &'a str,
    timestamp: &'a i64,
    model: &'a str,
    previous_message: &'a mut String,
    pin_message_id: &'a mut String,
    set_role: &'a mut bool,
}

/// Check if should skip conversion
fn should_skip_conversion(convo: &ConvoResponse, pin_message_id: &str) -> bool {
    if !pin_message_id.is_empty() {
        // Skip if message id is not equal to pin message id
        if convo.message_id() != pin_message_id {
            return false;
        }
    }

    let role_check = convo.role().ne(&Role::Assistant)
        || convo.raw_messages().is_empty()
        || convo.raw_messages()[0].is_empty();

    let metadata_check =
        convo.metadata_message_type() != "next" && convo.metadata_message_type() != "continue";

    role_check || metadata_check
}

pub(super) fn stream_handler(
    mut event_soure: EventStream<
        impl Stream<Item = Result<bytes::Bytes, reqwest::Error>> + std::marker::Unpin,
    >,
    model: String,
) -> Result<impl Stream<Item = Result<Event, Infallible>>, ResponseError> {
    let id = super::generate_id(29);
    let timestamp = super::current_timestamp()?;
    let stream = async_stream::stream! {
        let mut previous_message = String::new();
        let mut pin_message_id = String::new();
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

                            // Skip if role is not assistant
                            if should_skip_conversion(&convo, &pin_message_id) {
                                continue;
                            }

                            let mut context = HandlerContext {
                                stop: &mut stop,
                                id: &id,
                                timestamp: &timestamp,
                                model: &model,
                                previous_message: &mut previous_message,
                                pin_message_id: &mut pin_message_id,
                                set_role: &mut set_role,
                            };

                            if let Ok(event) = event_convert_handler(&mut context, convo).await {
                                if stop == 0 || stop <= 1 {
                                    yield Ok(event);
                                }
                            }
                        }
                    }
                },
                Err(err) => {
                    warn!("event-source stream error: {}", err);
                    break;
                }
            }

        }

        drop(event_soure)
    };
    Ok(stream)
}

async fn event_convert_handler(
    context: &mut HandlerContext<'_>,
    convo: ConvoResponse,
) -> ProxyResult<Event> {
    // Set pin message id
    if context.pin_message_id.is_empty() {
        context.pin_message_id.push_str(convo.message_id())
    }

    let message = convo
        .raw_messages()
        .first()
        .ok_or_else(|| ProxyError::BodyMessageIsEmpty)?;

    let finish_reason = convo
        .end_turn()
        .filter(|&end| end)
        .map(|_| convo.metadata_finish_details_type());

    let role = if *context.set_role {
        *context.set_role = false;
        Some(convo.role())
    } else {
        None
    };

    let return_message = if let Some("stop") = finish_reason.as_deref() {
        *context.stop += 1;
        None
    } else {
        Some(message.trim_start_matches(context.previous_message.as_str()))
    };

    context.previous_message.clear();
    context.previous_message.push_str(message);

    let delta = model::Delta::builder()
        .role(role)
        .content(return_message)
        .build();

    let resp = model::Resp::builder()
        .id(context.id)
        .object("chat.completion.chunk")
        .created(context.timestamp)
        .model(context.model)
        .choices(vec![model::Choice::builder()
            .index(0)
            .delta(Some(delta))
            .finish_reason(finish_reason)
            .build()])
        .build();

    let data = format!(
        " {}",
        serde_json::to_string(&resp).map_err(ProxyError::DeserializeError)?
    );
    Ok(Event::default().data(data))
}

pub(super) async fn not_stream_handler(
    mut event_soure: EventStream<
        impl Stream<Item = Result<bytes::Bytes, reqwest::Error>> + std::marker::Unpin,
    >,
    model: String,
) -> ProxyResult<Json<Value>> {
    let id = super::generate_id(29);
    let timestamp = super::current_timestamp()?;
    let mut previous_message = String::new();
    let mut finish_reason = None;

    while let Some(event_result) = event_soure.next().await {
        match event_result {
            Ok(event) => {
                // Break if event data is "[DONE]"
                if event.data.eq("[DONE]") {
                    break;
                }

                // Parse event data
                if let Ok(res) = serde_json::from_str::<PostConvoResponse>(&event.data) {
                    if let PostConvoResponse::Conversation(convo) = res {
                        let finish = convo.metadata_finish_details_type();
                        if !finish.is_empty() {
                            finish_reason = Some(finish.to_owned())
                        }

                        // If message is not empty, set previous message
                        if let Some(message) = convo.messages().first() {
                            previous_message.clear();
                            previous_message.push_str(message);
                        }

                        drop(convo)
                    }
                }
            }
            Err(err) => {
                warn!("event-source stream error: {}", err);
                drop(event_soure);
                return Err(ProxyError::EventSourceStreamError(err));
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
    let value = serde_json::to_value(&resp).map_err(ProxyError::DeserializeError)?;
    Ok(Json(value))
}
