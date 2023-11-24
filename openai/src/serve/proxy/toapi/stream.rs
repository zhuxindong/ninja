use axum::response::sse::Event;
use axum::Json;
use eventsource_stream::EventStream;
use futures::StreamExt;
use futures_core::Stream;
use serde_json::Value;
use std::convert::Infallible;

use crate::chatgpt::model::resp::{ConvoResponse, PostConvoResponse};
use crate::serve::error::ProxyError;
use crate::{chatgpt::model::Role, debug};

use super::model;

struct HandlerContext<'a> {
    stop: &'a mut u8,
    id: &'a str,
    timestamp: &'a i64,
    model: &'a str,
    previous_message: &'a mut String,
    set_role: &'a mut bool,
}

fn should_skip_conversion(convo: &ConvoResponse) -> bool {
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
) -> impl Stream<Item = Result<Event, Infallible>> {
    let id = super::generate_id(29);
    let timestamp = super::current_timestamp();
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

                            // Skip if role is not assistant
                            if should_skip_conversion(&convo) {
                                continue;
                            }

                            let mut context = HandlerContext {
                                stop: &mut stop,
                                id: &id,
                                timestamp: &timestamp,
                                model: &model,
                                previous_message: &mut previous_message,
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
                    debug!("event-source stream error: {}", err);
                }
            }
        }
    }
}

async fn event_convert_handler(
    context: &mut HandlerContext<'_>,
    convo: ConvoResponse,
) -> anyhow::Result<Event> {
    let messages = &convo.raw_messages();
    let message = messages
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

    let data = format!(" {}", serde_json::to_string(&resp)?);
    Ok(Event::default().data(data))
}

pub(super) async fn not_stream_handler(
    mut event_soure: EventStream<
        impl Stream<Item = Result<bytes::Bytes, reqwest::Error>> + std::marker::Unpin,
    >,
    model: String,
) -> anyhow::Result<Json<Value>> {
    let id = super::generate_id(29);
    let timestamp = super::current_timestamp();
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
