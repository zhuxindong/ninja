use serde::{Deserialize, Serialize};

use crate::context;

use super::Solver;

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
}

#[derive(Serialize, Debug)]
struct ReqBody<'a> {
    #[serde(rename = "clientKey")]
    client_key: &'a str,
    task: ReqTask<'a>,
    #[serde(rename = "softID", skip_serializing_if = "Option::is_none")]
    soft_id: Option<&'static str>,
    #[serde(rename = "appId", skip_serializing_if = "Option::is_none")]
    app_id: Option<&'static str>,
}

#[derive(Serialize, Debug)]
struct ReqTask<'a> {
    #[serde(rename = "type")]
    type_field: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    images: Option<Vec<String>>,
    question: &'a str,
}

#[derive(derive_builder::Builder)]
pub struct SubmitSolver<'a> {
    solved: &'a Solver,
    client_key: &'a str,
    #[builder(setter(into), default)]
    image: Option<String>,
    #[builder(setter(into), default)]
    images: Option<Vec<String>>,
    question: String,
}

pub async fn submit_task(submit_task: SubmitSolver<'_>) -> anyhow::Result<Vec<i32>> {
    let mut body = ReqBody {
        client_key: &submit_task.client_key,
        task: ReqTask {
            type_field: "FunCaptchaClassification",
            image: submit_task.image,
            images: submit_task.images,
            question: &submit_task.question,
        },
        soft_id: None,
        app_id: None,
    };

    let mut url = String::new();

    match submit_task.solved {
        Solver::Yescaptcha => {
            body.soft_id = Some("26299");
            url.push_str("https://api.yescaptcha.com/createTask")
        }
        Solver::Capsolver => {
            body.app_id = Some("60632CB0-8BE8-41D3-808F-60CC2442F16E");
            url.push_str("https://api.capsolver.com/createTask")
        }
    }

    let ctx = context::get_instance();
    let resp = ctx.client().post(url).json(&body).send().await?;

    match resp.error_for_status_ref() {
        Ok(_) => {
            let task = resp.json::<TaskResp>().await?;
            if let Some(error_description) = task.error_description {
                anyhow::bail!(format!("solver task error: {error_description}"))
            }
            let target = task.solution.objects;

            if target.is_empty() {
                anyhow::bail!(format!("solver task error: empty answer"))
            }
            Ok(target)
        }
        Err(err) => {
            let msg = resp.text().await?;
            anyhow::bail!(format!("solver task error: {err}\n{msg}"))
        }
    }
}
