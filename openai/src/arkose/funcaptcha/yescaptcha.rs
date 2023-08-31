use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::{arkose::CLIENT_HOLDER, debug};

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

pub async fn submit_task(
    client_key: &str,
    image_as_base64: &str,
    question: &str,
) -> anyhow::Result<i32> {
    let body = ReqBody {
        client_key,
        task: ReqTask {
            type_field: "FunCaptchaClassification",
            image: &image_as_base64,
            question: &question,
        },
        soft_id: "26299",
    };

    let client = CLIENT_HOLDER.get_instance();
    let resp = client
        .post("https://api.yescaptcha.com/createTask")
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() {
        let task = resp.json::<TaskResp>().await?;
        debug!("yescaptcha task: {task:#?}");
        if let Some(error_description) = task.error_description {
            anyhow::bail!(format!("yescaptcha task error:{error_description}"))
        }
        let target = task.solution.objects;
        return match target.is_empty() {
            true => Ok(0),
            false => Ok(target.get(0).context("funcaptcha valid error")?.clone()),
        };
    }
    anyhow::bail!("funcaptcha valid error")
}
