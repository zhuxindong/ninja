use serde::{Deserialize, Serialize};

use crate::{context::Context, debug};

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct TaskResp {
    #[serde(rename = "errorId")]
    error_id: i32,
    #[serde(rename = "errorCode")]
    error_code: String,
    #[serde(rename = "errorDescription")]
    error_description: Option<String>,
    status: String,
    solution: SolutionResp,
    #[serde(rename = "taskId")]
    task_id: String,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct SolutionResp {
    objects: Vec<i32>,
    labels: Vec<String>,
}

#[derive(Serialize, Debug)]
struct ReqBody<'a> {
    #[serde(rename = "clientKey")]
    client_key: &'a str,
    task: ReqTask<'a>,
    #[serde(rename = "softID")]
    soft_id: &'static str,
}

#[derive(Serialize, Debug)]
struct ReqTask<'a> {
    #[serde(rename = "type")]
    type_field: &'static str,
    image: &'a str,
    question: &'a str,
}

#[derive(derive_builder::Builder)]
pub struct SubmitTask {
    client_key: String,
    image_as_base64: String,
    question: String,
}

pub async fn submit_task(submit_task: SubmitTask) -> anyhow::Result<i32> {
    let body = ReqBody {
        client_key: &submit_task.client_key,
        task: ReqTask {
            type_field: "FunCaptchaClassification",
            image: &submit_task.image_as_base64,
            question: &submit_task.question,
        },
        soft_id: "26299",
    };

    let client = Context::get_instance().await;
    let resp = client
        .load_client()
        .post("https://api.yescaptcha.com/createTask")
        .json(&body)
        .send()
        .await?;

    match resp.error_for_status() {
        Ok(resp) => {
            let task = resp.json::<TaskResp>().await?;
            debug!("yescaptcha task: {task:#?}");
            if let Some(error_description) = task.error_description {
                anyhow::bail!(format!("yescaptcha task error: {error_description}"))
            }
            let target = task.solution.objects;
            return match target.is_empty() {
                true => Ok(0),
                false => {
                    Ok(anyhow::Context::context(target.get(0), "funcaptcha valid error")?.clone())
                }
            };
        }
        Err(err) => {
            anyhow::bail!("Error: {err}")
        }
    }
}
