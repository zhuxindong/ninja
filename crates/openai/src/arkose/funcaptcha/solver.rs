use std::str::FromStr;

use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;

use crate::{warn, with_context};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Solver {
    Yescaptcha,
    Capsolver,
}

impl Default for Solver {
    fn default() -> Self {
        Self::Yescaptcha
    }
}

impl FromStr for Solver {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "yescaptcha" => Ok(Self::Yescaptcha),
            "capsolver" => Ok(Self::Capsolver),
            _ => anyhow::bail!("Only support `yescaptcha` and `capsolver`"),
        }
    }
}

impl ToString for Solver {
    fn to_string(&self) -> String {
        match self {
            Self::Yescaptcha => "yescaptcha".to_string(),
            Self::Capsolver => "capsolver".to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArkoseSolver {
    pub solver: Solver,
    pub client_key: String,
}

impl ArkoseSolver {
    pub fn new(solver: Solver, client_key: String) -> Self {
        Self { solver, client_key }
    }
}

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

#[derive(TypedBuilder)]
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
            url.push_str("https://global.yescaptcha.com/createTask")
        }
        Solver::Capsolver => {
            body.app_id = Some("60632CB0-8BE8-41D3-808F-60CC2442F16E");
            url.push_str("https://api.capsolver.com/createTask")
        }
    }

    let resp = with_context!(arkose_client)
        .post(url)
        .json(&body)
        .send()
        .await?;

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
            warn!("submit task question error: {err}");
            let msg = resp.text().await?;
            anyhow::bail!(format!("solver task error: {err}\n{msg}"))
        }
    }
}
