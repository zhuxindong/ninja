use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{arkose::CLIENT_HOLDER, debug};

#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
struct Task {
    #[serde(rename = "errorId")]
    error_id: i32,
    #[serde(rename = "errorCode")]
    error_code: String,
    #[serde(rename = "errorDescription")]
    error_description: Option<String>,
    status: String,
    solution: Solution,
    #[serde(rename = "taskId")]
    task_id: String,
}

#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
struct Solution {
    objects: Vec<i32>,
    labels: Vec<String>,
}

pub async fn valid(client_key: &str, image_as_base64: &str, question: &str) -> anyhow::Result<i32> {
    let body = json!(
        {
            "clientKey": client_key,
            "task": {
                "type": "FunCaptchaClassification",
                "image": image_as_base64,
                "question": question
            }
        }
    );
    let client = CLIENT_HOLDER.get_instance();
    let resp = client
        .post("https://api.yescaptcha.com/createTask")
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() {
        let task = resp.json::<Task>().await?;
        debug!("yescaptcha task: {task:#?}");
        if let Some(error_description) = task.error_description {
            anyhow::bail!(format!("yescaptcha task error:{error_description}"))
        }
        let target = task.solution.objects;
        return match target.is_empty() {
            true => Ok(-1),
            false => Ok(target.get(0).context("funcaptcha valid error")?.clone()),
        };
    }
    anyhow::bail!("funcaptcha valid error")
}
