use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub(super) struct RequestChallenge<'a> {
    pub(super) sid: &'a str,
    pub(super) token: &'a str,
    pub(super) analytics_tier: i32,
    pub(super) render_type: &'a str,
    pub(super) lang: &'a str,
    #[serde(rename = "isAudioGame")]
    pub(super) is_audio_game: bool,
    #[serde(rename = "apiBreakerVersion")]
    pub(super) api_breaker_version: &'a str,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub(super) struct Challenge {
    pub(super) session_token: String,
    #[serde(rename = "challengeID")]
    pub(super) challenge_id: String,
    pub(super) game_data: GameData,
    pub(super) string_table: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub(super) struct GameData {
    #[serde(rename = "gameType")]
    pub(super) game_type: i32,
    pub(super) game_variant: String,
    pub(super) instruction_string: String,
    #[serde(rename = "customGUI")]
    pub(super) custom_gui: CustomGUI,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub(super) struct CustomGUI {
    #[serde(rename = "_challenge_imgs")]
    pub(super) challenge_imgs: Vec<String>,
    pub(super) api_breaker: ApiBreaker,
    pub(super) api_breaker_v2_enabled: isize,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct ApiBreaker {
    pub(super) key: String,
    pub(super) value: Vec<String>,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
pub(super) struct ConciseChallenge {
    pub(super) game_type: &'static str,
    pub(super) urls: Vec<String>,
    pub(super) instructions: String,
    pub(super) game_variant: String,
}

#[derive(Debug, Clone)]
pub struct FunCaptcha {
    pub image: String,
    pub instructions: String,
    pub game_variant: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct SubmitChallenge<'a> {
    pub(super) session_token: &'a str,
    pub(super) sid: &'a str,
    pub(super) game_token: &'a str,
    pub(super) guess: &'a str,
    pub(super) render_type: &'static str,
    pub(super) analytics_tier: i32,
    pub(super) bio: &'static str,
}
