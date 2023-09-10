use serde::{Deserialize, Serialize};

use crate::{context::Context, debug};

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
    image: &'a str,
    question: &'a str,
}

#[derive(derive_builder::Builder)]
pub struct SubmitSolver {
    solved: Solver,
    client_key: String,
    image_as_base64: String,
    question: String,
}

pub async fn submit_task(submit_task: SubmitSolver) -> anyhow::Result<i32> {
    let mut body = ReqBody {
        client_key: &submit_task.client_key,
        task: ReqTask {
            type_field: "FunCaptchaClassification",
            image: &submit_task.image_as_base64,
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

    let client = Context::get_instance().await;
    let resp = client.load_client().post(url).json(&body).send().await?;

    match resp.error_for_status() {
        Ok(resp) => {
            let task = resp.json::<TaskResp>().await?;
            debug!("solver captcha task: {task:#?}");
            if let Some(error_description) = task.error_description {
                anyhow::bail!(format!("yescaptcha task error: {error_description}"))
            }
            let target = task.solution.objects;
            return match target.is_empty() {
                true => Ok(0),
                false => {
                    Ok(anyhow::Context::context(target.get(0), "funcaptcha solver error")?.clone())
                }
            };
        }
        Err(err) => {
            anyhow::bail!("Error: {err}")
        }
    }
}
