pub mod crypto;
pub mod funcaptcha;
pub mod har;
pub mod murmur;

use std::path::Path;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use base64::Engine;
use rand::Rng;
use reqwest::header;
use reqwest::Method;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;

use crate::arkose::crypto::encrypt;
use crate::context::Context;
use crate::debug;
use crate::HEADER_UA;

use self::funcaptcha::solver::SubmitSolverBuilder;
use self::funcaptcha::Solver;

#[derive(PartialEq, Eq)]
pub enum GPT4Model {
    Gpt4model,
    Gpt4browsingModel,
    Gpt4pluginsModel,
    Gpt4Other,
}

impl TryFrom<&str> for GPT4Model {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "gpt-4" => Ok(GPT4Model::Gpt4model),
            "gpt-4-browsing" => Ok(GPT4Model::Gpt4browsingModel),
            "gpt-4-plugins" => Ok(GPT4Model::Gpt4pluginsModel),
            _ => {
                if value.starts_with("gpt-4") || value.starts_with("gpt4") {
                    return Ok(GPT4Model::Gpt4Other);
                }
                Err(())
            }
        }
    }
}

/// curl 'https://tcr9i.chat.openai.com/fc/gt2/public_key/35536E1E-65B4-4D96-9D97-6ADB7EFF8147' --data-raw 'public_key=35536E1E-65B4-4D96-9D97-6ADB7EFF8147'
#[derive(Deserialize, Debug)]
pub struct ArkoseToken {
    token: String,
}

impl ArkoseToken {
    pub fn value(&self) -> &str {
        &self.token
    }

    pub fn valid(&self) -> bool {
        self.token.contains("sup=1|rid=")
    }

    #[inline]
    pub async fn new() -> anyhow::Result<Self> {
        get_arkose_token().await
    }

    #[inline]
    pub async fn new_from_context() -> anyhow::Result<Self> {
        get_arkose_token_from_context().await
    }

    #[inline]
    pub async fn new_from_endpoint(endpoint: &str) -> anyhow::Result<Self> {
        get_arkose_token_from_endpoint(endpoint).await
    }

    #[inline]
    pub async fn new_form_har<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        get_arkose_token_from_har(path).await
    }
}

impl From<String> for ArkoseToken {
    fn from(value: String) -> Self {
        ArkoseToken { token: value }
    }
}

impl Serialize for ArkoseToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.token)
    }
}

#[inline]
async fn get_arkose_token() -> anyhow::Result<ArkoseToken> {
    let bx = serde_json::json!([{"key":"api_type","value":"js"},{"key":"p","value":1},{"key":"f","value":"d4d8b12394eb4648003e079234035d42"},{"key":"n","value":"MTY5NDI3MDc2MA=="},{"key":"wh","value":"2fb296ec17ca939d0821cf36f562d695|72627afbfd19a741c7da1732218301ac"},{"key":"enhanced_fp","value":[{"key":"webgl_extensions","value":"ANGLE_instanced_arrays;EXT_blend_minmax;EXT_color_buffer_half_float;EXT_disjoint_timer_query;EXT_float_blend;EXT_frag_depth;EXT_shader_texture_lod;EXT_texture_compression_bptc;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_color_buffer_float;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw"},{"key":"webgl_extensions_hash","value":"58a5a04a5bef1a78fa88d5c5098bd237"},{"key":"webgl_renderer","value":"WebKit WebGL"},{"key":"webgl_vendor","value":"WebKit"},{"key":"webgl_version","value":"WebGL 1.0 (OpenGL ES 2.0 Chromium)"},{"key":"webgl_shading_language_version","value":"WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)"},{"key":"webgl_aliased_line_width_range","value":"[1, 1]"},{"key":"webgl_aliased_point_size_range","value":"[1, 511]"},{"key":"webgl_antialiasing","value":"yes"},{"key":"webgl_bits","value":"8,8,24,8,8,0"},{"key":"webgl_max_params","value":"16,32,16384,1024,16384,16,16384,30,16,16,1024"},{"key":"webgl_max_viewport_dims","value":"[16384, 16384]"},{"key":"webgl_unmasked_vendor","value":"Apple Inc."},{"key":"webgl_unmasked_renderer","value":"AMD Radeon Pro Vega 56 OpenGL Engine"},{"key":"webgl_vsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_vsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_fsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_fsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_hash_webgl","value":"47a905e57bc9a6076d887b0332318f20"},{"key":"user_agent_data_brands","value":"Chromium,Not)A;Brand,Google Chrome"},{"key":"user_agent_data_mobile","value":false},{"key":"navigator_connection_downlink","value":1.1},{"key":"navigator_connection_downlink_max","value":null},{"key":"network_info_rtt","value":650},{"key":"network_info_save_data","value":false},{"key":"network_info_rtt_type","value":null},{"key":"screen_pixel_depth","value":24},{"key":"navigator_device_memory","value":4},{"key":"navigator_languages","value":"en-US,en"},{"key":"window_inner_width","value":0},{"key":"window_inner_height","value":0},{"key":"window_outer_width","value":1944},{"key":"window_outer_height","value":1301},{"key":"browser_detection_firefox","value":false},{"key":"browser_detection_brave","value":false},{"key":"audio_codecs","value":"{\"ogg\":\"probably\",\"mp3\":\"probably\",\"wav\":\"probably\",\"m4a\":\"maybe\",\"aac\":\"probably\"}"},{"key":"video_codecs","value":"{\"ogg\":\"probably\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"\",\"mpeg4a\":\"\",\"theora\":\"\"}"},{"key":"media_query_dark_mode","value":true},{"key":"headless_browser_phantom","value":false},{"key":"headless_browser_selenium","value":false},{"key":"headless_browser_nightmare_js","value":false},{"key":"document__referrer","value":"http://127.0.0.1:8000/"},{"key":"window__ancestor_origins","value":["https://chat.openai.com"]},{"key":"window__tree_index","value":[1]},{"key":"window__tree_structure","value":"[[],[]]"},{"key":"window__location_href","value":"https://tcr9i.chat.openai.com/v2/1.5.5/enforcement.fbfc14b0d793c6ef8359e0e4b4a91f67.html#35536E1E-65B4-4D96-9D97-6ADB7EFF8147"},{"key":"client_config__sitedata_location_href","value":"http://127.0.0.1:8000/arkose.html"},{"key":"client_config__surl","value":"https://tcr9i.chat.openai.com"},{"key":"mobile_sdk__is_sdk"},{"key":"client_config__language","value":null},{"key":"navigator_battery_charging","value":true},{"key":"audio_fingerprint","value":"124.04347651847638"}]},{"key":"fe","value":["DNT:unknown","L:en-US","D:24","PR:1","S:2560,1440","AS:2560,1345","TO:420","SS:true","LS:true","IDB:true","B:false","ODB:true","CPUC:unknown","PK:MacIntel","CFP:1855649544","FR:false","FOS:false","FB:false","JSF:","P:Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,WebKit built-in PDF","T:0,false,false","H:8","SWF:false"]},{"key":"ife_hash","value":"fa35325a5718d9a235c3a4aa060dc33b"},{"key":"cs","value":1},{"key":"jsbd","value":"{\"HL\":13,\"NCE\":true,\"DT\":\"\",\"NWD\":\"false\",\"DOTO\":1,\"DMTO\":1}"}]);
    let bv = HEADER_UA;

    let bt = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let bw = (bt - (bt % 21600)).to_string();

    let bda = encrypt(&bx.to_string(), &format!("{bv}{bw}"))?;

    let form: [(&str, &str); 8] = [
        ("public_key", "35536E1E-65B4-4D96-9D97-6ADB7EFF8147"),
        ("site", "https://chat.openai.com"),
        ("userbrowser", bv),
        ("capi_version", "1.5.2"),
        ("capi_mode", "lightbox"),
        ("style_theme", "default"),
        (
            "bda",
            &base64::engine::general_purpose::STANDARD.encode(&bda),
        ),
        ("rnd", &(&rand::thread_rng().gen::<f64>().to_string())),
    ];

    let client = Context::get_instance().await;
    let resp = client.load_client()
            .post("https://tcr9i.chat.openai.com/fc/gt2/public_key/35536E1E-65B4-4D96-9D97-6ADB7EFF8147")
            .header(header::USER_AGENT, HEADER_UA)
            .header(header::ACCEPT, "*/*")
            .header(header::ACCEPT_ENCODING, "gzip, deflate, br")
            .header(header::ACCEPT_LANGUAGE, "zh-CN,zh-Hans;q=0.9")
            .header(header::ORIGIN, "https://tcr9i.chat.openai.com")
            .header(header::REFERER, "https://tcr9i.chat.openai.com/v2/1.5.4/enforcement.cd12da708fe6cbe6e068918c38de2ad9.html")
            .header("Sec-Fetch-Dest", "empty")
            .header("Sec-Fetch-Mode", "cors")
            .header("Sec-Fetch-Sitet", "same-origin")
            .form(&form)
            .send().await?;

    if resp.status() != reqwest::StatusCode::OK {
        anyhow::bail!(format!("get arkose token status code {}", resp.status()));
    }

    Ok(resp.json::<ArkoseToken>().await?)
}

/// Build it yourself: https://github.com/gngpp/arkose-generator
async fn get_arkose_token_from_endpoint(endpoint: &str) -> anyhow::Result<ArkoseToken> {
    let client = Context::get_instance().await;
    let resp = client
        .load_client()
        .get(endpoint)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?;
    Ok(resp.json::<ArkoseToken>().await?)
}

#[inline]
async fn get_arkose_token_from_har<P: AsRef<Path>>(path: P) -> anyhow::Result<ArkoseToken> {
    let mut entry = har::parse_from_file(path)?;

    let bt = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let bw = bt - (bt % 21600);
    let bv = &entry.bv;
    let bx = &entry.bx;

    let bda = crypto::encrypt(bx, &format!("{bv}{bw}"))?;
    let rnd = format!("{}", rand::Rng::gen::<f64>(&mut rand::thread_rng()));

    entry.body.push_str(&format!(
        "&bda={}",
        base64::engine::general_purpose::STANDARD.encode(&bda)
    ));
    entry.body.push_str(&format!("&rnd={rnd}"));

    let client = Context::get_instance().await.load_client();

    let method = Method::from_bytes(entry.method.as_bytes())?;

    let mut builder = client
        .request(
            method,
            "https://tcr9i.chat.openai.com/fc/gt2/public_key/35536E1E-65B4-4D96-9D97-6ADB7EFF8147",
        )
        .timeout(std::time::Duration::from_secs(10));

    builder = builder.body(entry.body);

    for h in entry.headers.into_iter() {
        if h.name.eq_ignore_ascii_case("cookie") {
            let value = format!(
                "{};{}={}",
                h.value,
                generate_random_string(),
                generate_random_string()
            );
            builder = builder.header(h.name, value);
            continue;
        }
        builder = builder.header(h.name, h.value)
    }

    let res = builder.send().await?;
    match res.error_for_status() {
        Ok(resp) => Ok(resp.json::<ArkoseToken>().await?),
        Err(err) => Err(anyhow::anyhow!(err)),
    }
}

#[inline]
async fn get_arkose_token_from_context() -> anyhow::Result<ArkoseToken> {
    let ctx = Context::get_instance().await;

    if let Some(path) = ctx.arkose_har_file() {
        let token = submit_if_invalid(|| get_arkose_token_from_har(&path)).await?;
        return Ok(token);
    }

    if ctx.arkose_solver().is_some() {
        let token = submit_if_invalid(get_arkose_token).await?;
        return Ok(token);
    }

    if let Some(arkose_token_endpoint) = ctx.arkose_token_endpoint() {
        let token =
            submit_if_invalid(|| get_arkose_token_from_endpoint(arkose_token_endpoint)).await?;
        return Ok(token);
    }

    anyhow::bail!("There is no way to get arkose token")
}

#[inline]
async fn submit_if_invalid<F, Fut>(get_token: F) -> anyhow::Result<ArkoseToken>
where
    F: FnOnce() -> Fut,
    Fut: futures_core::Future<Output = anyhow::Result<ArkoseToken>>,
{
    let ctx = Context::get_instance().await;
    let arkose_token = get_token().await?;
    if arkose_token.valid() {
        Ok(arkose_token)
    } else if let Some(arkose_solver) = ctx.arkose_solver() {
        submit_captcha(
            &arkose_solver.solver,
            &arkose_solver.client_key,
            arkose_token,
        )
        .await
    } else {
        anyhow::bail!("No yescaptcha_client_key to submit captcha")
    }
}

#[inline]
async fn submit_captcha(
    solver: &Solver,
    key: &str,
    arkose_token: ArkoseToken,
) -> anyhow::Result<ArkoseToken> {
    let session = funcaptcha::start_challenge(arkose_token.value())
        .await
        .map_err(|error| anyhow::anyhow!(format!("Error creating session: {}", error)))?;

    let funs = anyhow::Context::context(session.funcaptcha(), "valid funcaptcha error")?;
    let max_cap = funs.len();
    let (tx, mut rx) = tokio::sync::mpsc::channel(max_cap);
    for (i, fun) in funs.into_iter().enumerate() {
        let sender = tx.clone();
        let submit_task = SubmitSolverBuilder::default()
            .solved(solver.clone())
            .client_key(key.to_string())
            .question(fun.instructions)
            .image_as_base64(fun.image)
            .build()?;
        tokio::spawn(async move {
            let res = funcaptcha::solver::submit_task(submit_task).await;
            sender.send((i, res)).await.expect("Send failed")
        });
    }

    // Wait for all tasks to complete
    let mut r = Vec::with_capacity(max_cap);
    for _ in 0..max_cap {
        if let Some((i, res)) = rx.recv().await {
            r.push((i, res?));
        }
    }

    r.sort_by_key(|&(i, _)| i);

    let answers = r
        .into_iter()
        .map(|(_, answer)| answer)
        .collect::<Vec<i32>>();

    return match session.submit_answer(answers).await {
        Ok(_) => {
            let new_token = arkose_token.value().replace("at=40", "at=40|sup=1");
            Ok(ArkoseToken::from(new_token))
        }
        Err(err) => {
            debug!("submit funcaptcha answer error: {err}");
            Ok(arkose_token)
        }
    };
}

pub fn generate_random_string() -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let mut rng = rand::thread_rng();
    let length = rng.gen_range(5..=15);

    let result: String = (0..length)
        .map(|_| {
            let index = rng.gen_range(0..CHARSET.len());
            CHARSET[index] as char
        })
        .collect();

    result
}
