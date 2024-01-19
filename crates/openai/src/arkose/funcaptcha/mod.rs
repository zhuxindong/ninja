mod breaker;
pub mod model;
pub mod solver;

use self::model::{Challenge, ConciseChallenge, FunCaptcha, RequestChallenge};
use super::{crypto, ArkoseToken};
use crate::arkose::error::ArkoseError;
use crate::arkose::funcaptcha::model::SubmitChallenge;
use crate::{debug, now_duration, warn, with_context};
use anyhow::{bail, Context};
use reqwest::header;
use serde::Deserialize;
use std::sync::Arc;

pub async fn start_challenge<'a>(arkose_token: &'a ArkoseToken) -> anyhow::Result<Session> {
    let value = arkose_token.value();
    let fields: Vec<&str> = value.split('|').collect();
    let session_token = fields.get(0).context("invalid arkose token")?.to_string();
    let sid = fields
        .get(1)
        .context("invalid arkose token")?
        .split('=')
        .nth(1)
        .unwrap_or_default();

    let mut headers = header::HeaderMap::new();
    headers.insert(header::REFERER, format!("https://tcr9i.chat.openai.com/fc/assets/ec-game-core/game-core/1.17.1/standard/index.html?session={}", value.replace("|", "&")).parse()?);
    headers.insert(header::DNT, header::HeaderValue::from_static("1"));

    let mut session = Session {
        arkose_token,
        sid: sid.to_owned(),
        session_token,
        funcaptcha: None,
        challenge: None,
        client: with_context!(arkose_client),
        game_type: 0,
        headers,
    };

    let concise_challenge = session.request_challenge().await?;

    let images = session
        .download_image_to_base64(&concise_challenge.urls)
        .await?;

    if concise_challenge.urls.len() >= 5 {
        warn!(
            "Funcaptcha images count >= 5, your features are already in high risk control status"
        );
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
pub struct Session<'a> {
    client: reqwest::Client,
    arkose_token: &'a ArkoseToken,
    sid: String,
    session_token: String,
    headers: header::HeaderMap,
    #[allow(dead_code)]
    challenge: Option<Challenge>,
    funcaptcha: Option<Arc<Vec<FunCaptcha>>>,
    game_type: u32,
}

impl<'a> Session<'_> {
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
        headers.insert("X-NewRelic-Timestamp", get_time_stamp()?.parse()?);

        let resp = self
            .client
            .post("https://openai-api.arkoselabs.com/fc/gfct/")
            .form(&challenge_request)
            .headers(headers)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!(
                "[https://openai-api.arkoselabs.com/fc/gfct/] status code: {}",
                resp.status().as_u16()
            )
        }

        let challenge = resp.json::<Challenge>().await?;
        debug!("challenge: {:#?}", challenge);

        self.game_type = challenge.game_data.game_type as u32;

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
                bail!("unknown challenge type key: {key}")
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
            let answer = breaker::hanlde_answer(
                c_ui.api_breaker_v2_enabled != 0,
                self.game_type,
                &c_ui.api_breaker,
                answer,
            )?
            .to_string();
            answer_index.push(answer)
        }

        let answer = answer_index.join(",");
        let submit = SubmitChallenge {
                    session_token: &self.session_token,
                    sid: &self.sid,
                    game_token: &self.challenge.as_ref().context("no challenge")?.challenge_id,
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
            .insert("X-NewRelic-Timestamp", get_time_stamp()?.parse()?);

        let resp = self
            .client
            .post("https://tcr9i.chat.openai.com/fc/ca/")
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
                let resp = resp
                    .json::<Response>()
                    .await
                    .map_err(ArkoseError::DeserializeError)?;

                if let Some(error) = resp.error {
                    anyhow::bail!(ArkoseError::FuncaptchaSubmitError(error))
                }

                if !resp.solved {
                    warn!("funcaptcha not solved: {:#?}", self.challenge);
                    anyhow::bail!(ArkoseError::FuncaptchaNotSolvedError(
                        resp.incorrect_guess.unwrap_or_default()
                    ))
                }

                // Callback
                let _ = self.arkose_token.callback().await;

                Ok(())
            }
            Err(err) => Err(anyhow::anyhow!(err)),
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

    pub fn funcaptcha(&self) -> Option<&Arc<Vec<FunCaptcha>>> {
        self.funcaptcha.as_ref()
    }
}

fn get_time_stamp() -> anyhow::Result<String> {
    let since_the_epoch = now_duration()?;
    Ok(since_the_epoch.as_millis().to_string())
}
