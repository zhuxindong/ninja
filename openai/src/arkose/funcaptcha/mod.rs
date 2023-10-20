pub mod solver;

use super::crypto;
use crate::{context, debug, warn};
use anyhow::{bail, Context};
use reqwest::header;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{collections::HashMap, str::FromStr};

const INIT_HEX: &str = "fbfc14b0d793c6ef8359e0e4b4a91f67";

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
    let ctx = context::get_instance();
    let mut session = Session {
        sid: sid.to_owned(),
        session_token: session_token.clone(),
        headers: header::HeaderMap::new(),
        challenge_logger: ChallengeLogger {
            sid: sid.to_owned(),
            session_token: session_token.clone(),
            analytics_tier: 40,
            render_type: "canvas".to_string(),
            game_token: None,
            game_type: None,
            category: None,
            action: None,
        },
        funcaptcha: None,
        challenge: None,
        client: ctx.client(),
    };

    session.headers.insert(header::REFERER, format!("https://client-api.arkoselabs.com/fc/assets/ec-game-core/game-core/1.15.0/standard/index.html?session={}", arkose_token.replace("|", "&")).parse()?);
    session
        .headers
        .insert(header::DNT, header::HeaderValue::from_static("1"));

    session
        .challenge_logger(
            "",
            0,
            "Site URL",
            format!("https://client-api.arkoselabs.com/v2/1.5.5/enforcement.{INIT_HEX}.html",),
        )
        .await?;

    let concise_challenge = session.request_challenge().await?;

    let images = session
        .download_image_to_base64(&concise_challenge.urls)
        .await?;

    debug!("instructions: {:#?}", concise_challenge.instructions);
    debug!("game_variant: {:#?}", concise_challenge.game_variant);
    debug!("images: {:#?}", concise_challenge.urls);

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
    challenge_logger: ChallengeLogger,
    funcaptcha: Option<Arc<Vec<FunCaptcha>>>,
}

impl Session {
    pub fn funcaptcha(&self) -> Option<&Arc<Vec<FunCaptcha>>> {
        self.funcaptcha.as_ref()
    }

    async fn challenge_logger(
        &self,
        game_token: &str,
        game_type: i32,
        category: &str,
        action: String,
    ) -> anyhow::Result<()> {
        let mut challenge_logger = self.challenge_logger.clone();
        challenge_logger.game_token = Some(game_token.to_string());

        if game_type != 0 {
            challenge_logger.game_type = Some(game_type.to_string());
        }

        challenge_logger.category = Some(category.to_string());
        challenge_logger.action = Some(action.to_string());

        let resp = self
            .client
            .post("https://client-api.arkoselabs.com/fc/a/")
            .form(&challenge_logger)
            .headers(self.headers.clone())
            .send()
            .await?;

        if let Some(err) = resp.error_for_status().err() {
            anyhow::bail!("[https://client-api.arkoselabs.com/fc/a/] status error: {err}")
        }

        Ok(())
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
        headers.insert("X-NewRelic-Timestamp", Self::get_time_stamp().parse()?);

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

        self.challenge_logger(
            &challenge.challenge_id,
            challenge.game_data.game_type,
            "loaded",
            "game loaded".to_owned(),
        )
        .await?;

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
        for answer in answers {
            answer_index.push(format!(r#"{{"index":{answer}}}"#))
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

        self.headers.insert("X-Requested-ID", request_id.parse()?);

        self.headers
            .insert("X-NewRelic-Timestamp", Self::get_time_stamp().parse()?);

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

    fn get_time_stamp() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now();
        let since_the_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
        since_the_epoch.as_millis().to_string()
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

#[derive(Debug, Serialize)]
struct RequestChallenge<'a> {
    sid: &'a str,
    token: &'a str,
    analytics_tier: i32,
    render_type: &'a str,
    lang: &'a str,
    #[serde(rename = "isAudioGame")]
    is_audio_game: bool,
    #[serde(rename = "apiBreakerVersion")]
    api_breaker_version: &'a str,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct Challenge {
    session_token: String,
    #[serde(rename = "challengeID")]
    challenge_id: String,
    #[serde(rename = "challengeURL")]
    challenge_url: String,
    audio_challenge_urls: Option<Vec<String>>,
    game_data: GameData,
    string_table: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct GameData {
    #[serde(rename = "gameType")]
    game_type: i32,
    game_variant: String,
    instruction_string: String,
    #[serde(rename = "customGUI")]
    custom_gui: CustomGUI,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct CustomGUI {
    #[serde(rename = "_challenge_imgs")]
    challenge_imgs: Vec<String>,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
struct ConciseChallenge {
    game_type: &'static str,
    urls: Vec<String>,
    instructions: String,
    game_variant: String,
}

#[derive(Debug, Serialize, Clone)]
struct ChallengeLogger {
    sid: String,
    session_token: String,
    analytics_tier: i32,
    render_type: String,
    game_token: Option<String>,
    game_type: Option<String>,
    category: Option<String>,
    action: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FunCaptcha {
    pub image: String,
    pub instructions: String,
    pub game_variant: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SubmitChallenge<'a> {
    session_token: &'a str,
    sid: &'a str,
    game_token: &'a str,
    guess: &'a str,
    render_type: &'static str,
    analytics_tier: i32,
    bio: &'static str,
}
