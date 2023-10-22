pub mod model;
pub mod solver;

use self::model::{ApiBreaker, Challenge, ConciseChallenge, FunCaptcha, RequestChallenge};

use super::crypto;
use crate::arkose::funcaptcha::model::SubmitChallenge;
use crate::{context, warn};
use anyhow::{bail, Context};
use rand::Rng;
use reqwest::header;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;

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

pub async fn start_challenge(arkose_token: &str) -> anyhow::Result<Session> {
    let fields: Vec<&str> = arkose_token.split('|').collect();
    let session_token = fields[0].to_string();
    let sid = fields[1].split('=').nth(1).unwrap_or_default();
    let mut session = Session {
        sid: sid.to_owned(),
        session_token: session_token.clone(),
        headers: header::HeaderMap::new(),
        funcaptcha: None,
        challenge: None,
        client: context::get_instance().client(),
    };

    session.headers.insert(header::REFERER, format!("https://client-api.arkoselabs.com/fc/assets/ec-game-core/game-core/1.15.0/standard/index.html?session={}", arkose_token.replace("|", "&")).parse()?);
    session
        .headers
        .insert(header::DNT, header::HeaderValue::from_static("1"));

    let concise_challenge = session.request_challenge().await?;

    let images = session
        .download_image_to_base64(&concise_challenge.urls)
        .await?;

    if concise_challenge.urls.len() >= 5 {
        warn!("funcaptcha images count >= 10, please use `solver: capsolver`");
    }

    let funcaptcha_list = images
        .into_iter()
        .map(|image| FunCaptcha {
            image,
            instructions: concise_challenge.instructions.clone(),
            game_variant: concise_challenge.game_variant.clone(),
        })
        .collect::<Vec<FunCaptcha>>();

    session.funcaptcha = Some(Arc::new(funcaptcha_list));

    Ok(session)
}

#[derive(Debug)]
pub struct Session {
    client: reqwest::Client,
    sid: String,
    session_token: String,
    headers: header::HeaderMap,
    #[allow(dead_code)]
    challenge: Option<Challenge>,
    funcaptcha: Option<Arc<Vec<FunCaptcha>>>,
}

impl Session {
    pub fn funcaptcha(&self) -> Option<&Arc<Vec<FunCaptcha>>> {
        self.funcaptcha.as_ref()
    }

    #[inline]
    async fn request_challenge(&mut self) -> anyhow::Result<ConciseChallenge> {
        let challenge_request = RequestChallenge {
            sid: &self.sid,
            token: &self.session_token,
            analytics_tier: 40,
            render_type: "canvas",
            lang: "en-us",
            is_audio_game: false,
            api_breaker_version: "green",
        };

        let mut headers = self.headers.clone();
        headers.insert("X-NewRelic-Timestamp", get_time_stamp().parse()?);

        let resp = self
            .client
            .post("https://client-api.arkoselabs.com/fc/gfct/")
            .form(&challenge_request)
            .headers(headers)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!(
                "[https://client-api.arkoselabs.com/fc/gfct/] status code: {}",
                resp.status().as_u16()
            )
        }

        let challenge = resp.json::<Challenge>().await?;

        // Build concise challenge
        let (game_type, challenge_urls, key, game_variant) = {
            let game_variant = if challenge.game_data.instruction_string.is_empty() {
                &challenge.game_data.game_variant
            } else {
                &challenge.game_data.instruction_string
            };

            (
                "image",
                &challenge.game_data.custom_gui.challenge_imgs,
                format!(
                    "{}.instructions-{game_variant}",
                    challenge.game_data.game_type
                ),
                game_variant.to_owned(),
            )
        };

        let remove_html_tags = |input: &str| {
            let re = regex::Regex::new(r"<[^>]*>").expect("invalid regex");
            re.replace_all(input, "").to_string()
        };

        match challenge.string_table.get(&key) {
            Some(html_instructions) => {
                let concise_challenge = ConciseChallenge {
                    game_type,
                    game_variant,
                    urls: challenge_urls.to_vec(),
                    instructions: remove_html_tags(html_instructions),
                };
                self.challenge = Some(challenge);
                Ok(concise_challenge)
            }
            None => {
                warn!("unknown challenge type: {challenge:#?}");
                bail!("unknown challenge type: {key}")
            }
        }
    }

    pub async fn submit_answer(mut self, answers: Vec<i32>) -> anyhow::Result<()> {
        let mut answer_index = Vec::with_capacity(answers.len());
        let c_ui = &self
            .challenge
            .as_ref()
            .context("no challenge")?
            .game_data
            .custom_gui;

        for answer in answers {
            if c_ui.api_breaker_v2_enabled != 0 {
                let answer = hanlde_answer(answer, &c_ui.api_breaker);
                answer_index.push(answer.to_string())
            } else {
                answer_index.push(format!(r#"{{"index":{answer}}}"#))
            }
        }

        let answer = answer_index.join(",");
        let submit = SubmitChallenge {
                    session_token: &self.session_token,
                    sid: &self.sid,
                    game_token: &self.challenge.context("no challenge")?.challenge_id,
                    guess: &crypto::encrypt(&format!("[{answer}]"), &self.session_token)?,
                    render_type: "canvas",
                    analytics_tier: 40,
                    bio: "eyJtYmlvIjoiMTUwLDAsMTE3LDIzOTszMDAsMCwxMjEsMjIxOzMxNywwLDEyNCwyMTY7NTUwLDAsMTI5LDIxMDs1NjcsMCwxMzQsMjA3OzYxNywwLDE0NCwyMDU7NjUwLDAsMTU1LDIwNTs2NjcsMCwxNjUsMjA1OzY4NCwwLDE3MywyMDc7NzAwLDAsMTc4LDIxMjs4MzQsMCwyMjEsMjI4OzI2MDY3LDAsMTkzLDM1MTsyNjEwMSwwLDE4NSwzNTM7MjYxMDEsMCwxODAsMzU3OzI2MTM0LDAsMTcyLDM2MTsyNjE4NCwwLDE2NywzNjM7MjYyMTcsMCwxNjEsMzY1OzI2MzM0LDAsMTU2LDM2NDsyNjM1MSwwLDE1MiwzNTQ7MjYzNjcsMCwxNTIsMzQzOzI2Mzg0LDAsMTUyLDMzMTsyNjQ2NywwLDE1MSwzMjU7MjY0NjcsMCwxNTEsMzE3OzI2NTAxLDAsMTQ5LDMxMTsyNjY4NCwxLDE0NywzMDc7MjY3NTEsMiwxNDcsMzA3OzMwNDUxLDAsMzcsNDM3OzMwNDY4LDAsNTcsNDI0OzMwNDg0LDAsNjYsNDE0OzMwNTAxLDAsODgsMzkwOzMwNTAxLDAsMTA0LDM2OTszMDUxOCwwLDEyMSwzNDk7MzA1MzQsMCwxNDEsMzI0OzMwNTUxLDAsMTQ5LDMxNDszMDU4NCwwLDE1MywzMDQ7MzA2MTgsMCwxNTUsMjk2OzMwNzUxLDAsMTU5LDI4OTszMDc2OCwwLDE2NywyODA7MzA3ODQsMCwxNzcsMjc0OzMwODE4LDAsMTgzLDI3MDszMDg1MSwwLDE5MSwyNzA7MzA4ODQsMCwyMDEsMjY4OzMwOTE4LDAsMjA4LDI2ODszMTIzNCwwLDIwNCwyNjM7MzEyNTEsMCwyMDAsMjU3OzMxMzg0LDAsMTk1LDI1MTszMTQxOCwwLDE4OSwyNDk7MzE1NTEsMSwxODksMjQ5OzMxNjM0LDIsMTg5LDI0OTszMTcxOCwxLDE4OSwyNDk7MzE3ODQsMiwxODksMjQ5OzMxODg0LDEsMTg5LDI0OTszMTk2OCwyLDE4OSwyNDk7MzIyODQsMCwyMDIsMjQ5OzMyMzE4LDAsMjE2LDI0NzszMjMxOCwwLDIzNCwyNDU7MzIzMzQsMCwyNjksMjQ1OzMyMzUxLDAsMzAwLDI0NTszMjM2OCwwLDMzOSwyNDE7MzIzODQsMCwzODgsMjM5OzMyNjE4LDAsMzkwLDI0NzszMjYzNCwwLDM3NCwyNTM7MzI2NTEsMCwzNjUsMjU1OzMyNjY4LDAsMzUzLDI1NzszMjk1MSwxLDM0OCwyNTc7MzMwMDEsMiwzNDgsMjU3OzMzNTY4LDAsMzI4LDI3MjszMzU4NCwwLDMxOSwyNzg7MzM2MDEsMCwzMDcsMjg2OzMzNjUxLDAsMjk1LDI5NjszMzY1MSwwLDI5MSwzMDA7MzM2ODQsMCwyODEsMzA5OzMzNjg0LDAsMjcyLDMxNTszMzcxOCwwLDI2NiwzMTc7MzM3MzQsMCwyNTgsMzIzOzMzNzUxLDAsMjUyLDMyNzszMzc1MSwwLDI0NiwzMzM7MzM3NjgsMCwyNDAsMzM3OzMzNzg0LDAsMjM2LDM0MTszMzgxOCwwLDIyNywzNDc7MzM4MzQsMCwyMjEsMzUzOzM0MDUxLDAsMjE2LDM1NDszNDA2OCwwLDIxMCwzNDg7MzQwODQsMCwyMDQsMzQ0OzM0MTAxLDAsMTk4LDM0MDszNDEzNCwwLDE5NCwzMzY7MzQ1ODQsMSwxOTIsMzM0OzM0NjUxLDIsMTkyLDMzNDsiLCJ0YmlvIjoiIiwia2JpbyI6IiJ9",
                };

        let pwd = format!("REQUESTED{}ID", self.session_token);

        let request_id = crypto::encrypt("{{\"sc\":[147,307]}}", &pwd)?;

        self.headers
            .insert(header::DNT, header::HeaderValue::from_static("1"));
        self.headers.insert("X-Requested-ID", request_id.parse()?);

        self.headers
            .insert("X-NewRelic-Timestamp", get_time_stamp().parse()?);

        let resp = self
            .client
            .post("https://client-api.arkoselabs.com/fc/ca/")
            .headers(self.headers)
            .form(&submit)
            .send()
            .await?;

        #[derive(Deserialize, Default, Debug)]
        #[serde(default)]
        struct Response {
            response: Option<String>,
            solved: bool,
            incorrect_guess: Option<String>,
            score: i32,
            error: Option<String>,
        }

        match resp.error_for_status() {
            Ok(resp) => {
                let resp = resp.json::<Response>().await?;

                if let Some(error) = resp.error {
                    anyhow::bail!("funcaptcha submit error {error}")
                }

                if !resp.solved {
                    anyhow::bail!(
                        "incorrect guess {}",
                        resp.incorrect_guess.unwrap_or_default()
                    )
                }
                Ok(())
            }
            Err(err) => {
                anyhow::bail!(err)
            }
        }
    }

    async fn download_image_to_base64(&self, urls: &Vec<String>) -> anyhow::Result<Vec<String>> {
        use base64::{engine::general_purpose, Engine as _};
        let mut b64_imgs = Vec::new();
        for url in urls {
            let bytes = self
                .client
                .get(url)
                .headers(self.headers.clone())
                .send()
                .await?
                .bytes()
                .await?;
            let b64 = general_purpose::STANDARD.encode(bytes);
            b64_imgs.push(b64);
        }

        Ok(b64_imgs)
    }
}

fn hanlde_api_breaker_key(key: &str) -> Box<dyn Fn(i32) -> i32> {
    match key {
        "alpha" => Box::new(|answer| {
            let y_value_str = answer.to_string();
            let combined_str = y_value_str + &1.to_string();
            let combined_int = combined_str.parse::<i32>().unwrap();
            combined_int - 2
        }),
        "beta" => Box::new(|answer| -answer),
        "gamma" => Box::new(|answer| 3 * (3 - answer)),
        "delta" => Box::new(|answer| 7 * answer),
        "epsilon" => Box::new(|answer| 2 * answer),
        "zeta" => Box::new(|answer| if answer != 0 { 100 / answer } else { answer }),
        _ => Box::new(|answer| answer),
    }
}

fn hanlde_api_breaker_value(key: &str) -> Box<dyn Fn(i32) -> serde_json::Value> {
    return match key {
        "alpha" => Box::new(|answer| {
            let v = [
                rand::thread_rng().gen_range(0..100),
                answer,
                rand::thread_rng().gen_range(0..100),
            ];
            json!(v)
        }),
        "beta" => Box::new(|answer| {
            json!({
                "size": 50 - answer,
                "id": answer,
                "limit": 10 * answer,
                "req_timestamp": get_time_stamp(),
            })
        }),
        "delta" => Box::new(|answer| {
            json!({
                "index": answer,
            })
        }),
        "epsilon" => Box::new(|answer| {
            let array_len = rand::thread_rng().gen_range(0..5) + 1;
            let rand_index = rand::thread_rng().gen_range(0..array_len);

            let mut arr = Vec::with_capacity(array_len);
            for i in 0..array_len {
                if i == rand_index {
                    arr[i] = answer;
                } else {
                    arr[i] = rand::thread_rng().gen_range(0..10);
                }
            }
            arr.push(rand_index as i32);
            json!(arr)
        }),
        "zeta" => Box::new(|answer| {
            let array_len = rand::thread_rng().gen_range(0..5) + 1;
            let mut vec = vec![0; array_len];
            vec.push(answer);
            json!(vec)
        }),
        "gamma" | _ => Box::new(|answer| json!(answer)),
    };
}

fn hanlde_answer(mut answer: i32, api_breaker: &ApiBreaker) -> serde_json::Value {
    for v in &api_breaker.value {
        answer = hanlde_api_breaker_key(&v)(answer)
    }
    hanlde_api_breaker_value(&api_breaker.key)(answer)
}

fn get_time_stamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now();
    let since_the_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
    since_the_epoch.as_millis().to_string()
}
