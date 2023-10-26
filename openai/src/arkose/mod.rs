pub mod crypto;
pub mod funcaptcha;
pub mod har;
pub mod murmur;

use base64::engine::general_purpose;
use std::path::Path;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use base64::Engine;
use rand::Rng;
use regex::Regex;
use reqwest::header;
use reqwest::Method;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;
use tokio::sync::OnceCell;

use crate::arkose::crypto::encrypt;
use crate::context;
use crate::generate_random_string;
use crate::warn;
use crate::HEADER_UA;

use self::funcaptcha::solver::SubmitSolver;
use self::funcaptcha::Solver;

#[derive(Hash, PartialEq, Eq, Debug)]
pub enum Type {
    Chat3,
    Chat4,
    Platform,
    Auth0,
}

impl std::str::FromStr for Type {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "chat3" => Ok(Type::Chat3),
            "chat4" => Ok(Type::Chat4),
            "platform" => Ok(Type::Platform),
            "auth0" => Ok(Type::Auth0),
            _ => anyhow::bail!("Invalid type"),
        }
    }
}

#[derive(PartialEq, Eq)]
pub enum GPTModel {
    Gpt35Model,
    Gpt35Other,
    Gpt4Model,
    Gpt4Other,
}

impl Into<Type> for GPTModel {
    fn into(self) -> Type {
        match self {
            GPTModel::Gpt35Other | GPTModel::Gpt35Model => Type::Chat3,
            GPTModel::Gpt4Other | GPTModel::Gpt4Model => Type::Chat4,
        }
    }
}

impl std::str::FromStr for GPTModel {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "gpt-4" => Ok(GPTModel::Gpt4Model),
            "gpt-3.5" => Ok(GPTModel::Gpt35Model),
            s if s.starts_with("gpt-4") || s.starts_with("gpt4") => Ok(GPTModel::Gpt4Other),
            s if s.starts_with("gpt-3.5") || s.starts_with("text-davinci") => {
                Ok(GPTModel::Gpt35Other)
            }
            _ => anyhow::bail!("Invalid GPT model"),
        }
    }
}

/// curl 'https://tcr9i.chat.openai.com/fc/gt2/public_key/35536E1E-65B4-4D96-9D97-6ADB7EFF8147' --data-raw 'public_key=35536E1E-65B4-4D96-9D97-6ADB7EFF8147'
#[derive(Deserialize, Debug)]
pub struct ArkoseToken {
    token: String,
}

impl From<&str> for ArkoseToken {
    fn from(value: &str) -> Self {
        ArkoseToken {
            token: value.to_owned(),
        }
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

static CHAT3_BX: OnceCell<String> = OnceCell::const_new();
static CHAT4_BX: OnceCell<String> = OnceCell::const_new();
static AUTH0_BX: OnceCell<String> = OnceCell::const_new();
static PLATFORM_BX: OnceCell<String> = OnceCell::const_new();

impl ArkoseToken {
    /// Get ArkoseLabs token
    pub fn value(&self) -> &str {
        &self.token
    }

    /// Check if the token is valid
    pub fn success(&self) -> bool {
        self.token.contains("sup=1|rid=")
    }

    pub async fn new(t: Type) -> anyhow::Result<Self> {
        match t {
            Type::Chat3 => {
                let bx = CHAT3_BX.get_or_init(|| async {
                    let bx_json = serde_json::json!([{"key":"api_type","value":"js"},{"key":"p","value":1},{"key":"f","value":"361215765a2ed02bf3f3c4e1a4f501a7"},{"key":"n","value":"MTY5ODEyMjE3MA=="},{"key":"wh","value":"9dff3eaaff9e5adc21363223db5d794e|1d99c2530fa1a96e676f9b1a1a9bcb58"},{"key":"enhanced_fp","value":[{"key":"webgl_extensions","value":"ANGLE_instanced_arrays;EXT_blend_minmax;EXT_color_buffer_half_float;EXT_float_blend;EXT_frag_depth;EXT_shader_texture_lod;EXT_texture_compression_bptc;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_color_buffer_float;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw"},{"key":"webgl_extensions_hash","value":"c70a87fa6fd567ea635c3a19c9f4c23a"},{"key":"webgl_renderer","value":"WebKit WebGL"},{"key":"webgl_vendor","value":"WebKit"},{"key":"webgl_version","value":"WebGL 1.0"},{"key":"webgl_shading_language_version","value":"WebGL GLSL ES 1.0 (1.0)"},{"key":"webgl_aliased_line_width_range","value":"[1, 1]"},{"key":"webgl_aliased_point_size_range","value":"[1, 511]"},{"key":"webgl_antialiasing","value":"yes"},{"key":"webgl_bits","value":"8,8,24,8,8,0"},{"key":"webgl_max_params","value":"16,32,16384,1024,16384,16,16384,30,16,16,1024"},{"key":"webgl_max_viewport_dims","value":"[16384, 16384]"},{"key":"webgl_unmasked_vendor","value":"Apple Inc."},{"key":"webgl_unmasked_renderer","value":"Apple GPU"},{"key":"webgl_vsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_vsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_fsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_fsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_hash_webgl","value":"3b034c93c1aa31e9cda3e5311c25db5e"},{"key":"user_agent_data_brands","value":null},{"key":"user_agent_data_mobile","value":null},{"key":"navigator_connection_downlink","value":null},{"key":"navigator_connection_downlink_max","value":null},{"key":"network_info_rtt","value":null},{"key":"network_info_save_data","value":null},{"key":"network_info_rtt_type","value":null},{"key":"screen_pixel_depth","value":24},{"key":"navigator_device_memory","value":null},{"key":"navigator_languages","value":"zh-CN"},{"key":"window_inner_width","value":0},{"key":"window_inner_height","value":0},{"key":"window_outer_width","value":1995},{"key":"window_outer_height","value":1344},{"key":"browser_detection_firefox","value":false},{"key":"browser_detection_brave","value":false},{"key":"audio_codecs","value":"{\"ogg\":\"\",\"mp3\":\"maybe\",\"wav\":\"\",\"m4a\":\"maybe\",\"aac\":\"maybe\"}"},{"key":"video_codecs","value":"{\"ogg\":\"\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"probably\",\"mpeg4a\":\"probably\",\"theora\":\"\"}"},{"key":"media_query_dark_mode","value":true},{"key":"headless_browser_phantom","value":false},{"key":"headless_browser_selenium","value":false},{"key":"headless_browser_nightmare_js","value":false},{"key":"document__referrer","value":""},{"key":"window__ancestor_origins","value":["https://chat.openai.com"]},{"key":"window__tree_index","value":[1]},{"key":"window__tree_structure","value":"[[],[]]"},{"key":"window__location_href","value":"https://tcr9i.chat.openai.com/v2/1.5.5/enforcement.fbfc14b0d793c6ef8359e0e4b4a91f67.html#3D86FBBA-9D22-402A-B512-3420086BA6CC"},{"key":"client_config__sitedata_location_href","value":"https://chat.openai.com/"},{"key":"client_config__surl","value":"https://tcr9i.chat.openai.com"},{"key":"mobile_sdk__is_sdk"},{"key":"client_config__language","value":null},{"key":"audio_fingerprint","value":"124.04345808873768"}]},{"key":"fe","value":["DNT:unknown","L:zh-CN","D:24","PR:1","S:2560,1440","AS:2560,1345","TO:-480","SS:true","LS:true","IDB:true","B:false","ODB:false","CPUC:unknown","PK:MacIntel","CFP:-432418192","FR:false","FOS:false","FB:false","JSF:Andale Mono,Arial,Arial Black,Arial Hebrew,Arial Narrow,Arial Rounded MT Bold,Arial Unicode MS,Comic Sans MS,Courier,Courier New,Geneva,Georgia,Helvetica,Helvetica Neue,Impact,LUCIDA GRANDE,Microsoft Sans Serif,Monaco,Palatino,Tahoma,Times,Times New Roman,Trebuchet MS,Verdana,Wingdings,Wingdings 2,Wingdings 3","P:Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,WebKit built-in PDF","T:0,false,false","H:8","SWF:false"]},{"key":"ife_hash","value":"a6c256ba86359de6e3b0b4ae46fe4b2a"},{"key":"cs","value":1},{"key":"jsbd","value":"{\"HL\":2,\"NCE\":true,\"DT\":\"\",\"NWD\":\"false\",\"DOTO\":1,\"DMTO\":1}"}]);
                    bx_json.to_string()
                }).await;
                get_chat3_from_bx(bx).await
            }
            Type::Chat4 => {
                let bx = CHAT4_BX.get_or_init(|| async {
                    let bx_json = serde_json::json!([{"key":"api_type","value":"js"},{"key":"p","value":1},{"key":"f","value":"d4d8b12394eb4648003e079234035d42"},{"key":"n","value":"MTY5NDI3MDc2MA=="},{"key":"wh","value":"2fb296ec17ca939d0821cf36f562d695|72627afbfd19a741c7da1732218301ac"},{"key":"enhanced_fp","value":[{"key":"webgl_extensions","value":"ANGLE_instanced_arrays;EXT_blend_minmax;EXT_color_buffer_half_float;EXT_disjoint_timer_query;EXT_float_blend;EXT_frag_depth;EXT_shader_texture_lod;EXT_texture_compression_bptc;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_color_buffer_float;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw"},{"key":"webgl_extensions_hash","value":"58a5a04a5bef1a78fa88d5c5098bd237"},{"key":"webgl_renderer","value":"WebKit WebGL"},{"key":"webgl_vendor","value":"WebKit"},{"key":"webgl_version","value":"WebGL 1.0 (OpenGL ES 2.0 Chromium)"},{"key":"webgl_shading_language_version","value":"WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)"},{"key":"webgl_aliased_line_width_range","value":"[1, 1]"},{"key":"webgl_aliased_point_size_range","value":"[1, 511]"},{"key":"webgl_antialiasing","value":"yes"},{"key":"webgl_bits","value":"8,8,24,8,8,0"},{"key":"webgl_max_params","value":"16,32,16384,1024,16384,16,16384,30,16,16,1024"},{"key":"webgl_max_viewport_dims","value":"[16384, 16384]"},{"key":"webgl_unmasked_vendor","value":"Apple Inc."},{"key":"webgl_unmasked_renderer","value":"AMD Radeon Pro Vega 56 OpenGL Engine"},{"key":"webgl_vsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_vsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_fsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_fsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_hash_webgl","value":"47a905e57bc9a6076d887b0332318f20"},{"key":"user_agent_data_brands","value":"Chromium,Not)A;Brand,Google Chrome"},{"key":"user_agent_data_mobile","value":false},{"key":"navigator_connection_downlink","value":1.1},{"key":"navigator_connection_downlink_max","value":null},{"key":"network_info_rtt","value":650},{"key":"network_info_save_data","value":false},{"key":"network_info_rtt_type","value":null},{"key":"screen_pixel_depth","value":24},{"key":"navigator_device_memory","value":4},{"key":"navigator_languages","value":"en-US,en"},{"key":"window_inner_width","value":0},{"key":"window_inner_height","value":0},{"key":"window_outer_width","value":1944},{"key":"window_outer_height","value":1301},{"key":"browser_detection_firefox","value":false},{"key":"browser_detection_brave","value":false},{"key":"audio_codecs","value":"{\"ogg\":\"probably\",\"mp3\":\"probably\",\"wav\":\"probably\",\"m4a\":\"maybe\",\"aac\":\"probably\"}"},{"key":"video_codecs","value":"{\"ogg\":\"probably\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"\",\"mpeg4a\":\"\",\"theora\":\"\"}"},{"key":"media_query_dark_mode","value":true},{"key":"headless_browser_phantom","value":false},{"key":"headless_browser_selenium","value":false},{"key":"headless_browser_nightmare_js","value":false},{"key":"document__referrer","value":"http://127.0.0.1:8000/"},{"key":"window__ancestor_origins","value":["https://chat.openai.com"]},{"key":"window__tree_index","value":[1]},{"key":"window__tree_structure","value":"[[],[]]"},{"key":"window__location_href","value":"https://tcr9i.chat.openai.com/v2/1.5.5/enforcement.fbfc14b0d793c6ef8359e0e4b4a91f67.html#35536E1E-65B4-4D96-9D97-6ADB7EFF8147"},{"key":"client_config__sitedata_location_href","value":"https://chat.openai.com/"},{"key":"client_config__surl","value":"https://tcr9i.chat.openai.com"},{"key":"mobile_sdk__is_sdk"},{"key":"client_config__language","value":null},{"key":"navigator_battery_charging","value":true},{"key":"audio_fingerprint","value":"124.04347651847638"}]},{"key":"fe","value":["DNT:unknown","L:en-US","D:24","PR:1","S:2560,1440","AS:2560,1345","TO:420","SS:true","LS:true","IDB:true","B:false","ODB:true","CPUC:unknown","PK:MacIntel","CFP:1855649544","FR:false","FOS:false","FB:false","JSF:","P:Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,WebKit built-in PDF","T:0,false,false","H:8","SWF:false"]},{"key":"ife_hash","value":"fa35325a5718d9a235c3a4aa060dc33b"},{"key":"cs","value":1},{"key":"jsbd","value":"{\"HL\":13,\"NCE\":true,\"DT\":\"\",\"NWD\":\"false\",\"DOTO\":1,\"DMTO\":1}"}]);
                    bx_json.to_string()
                }).await;
                get_chat4_from_bx(bx).await
            }
            Type::Auth0 => {
                let bx = AUTH0_BX.get_or_init(|| async {
                    let bx_json = serde_json::json!([{"key":"api_type","value":"js"},{"key":"p","value":1},{"key":"f","value":"fc7e35accfb122a7dd6099148ce96917"},{"key":"n","value":"MTY5NTcwMjYyNw=="},{"key":"wh","value":"04422442121a388db7bf68f6ce3ae8ca|72627afbfd19a741c7da1732218301ac"},{"key":"enhanced_fp","value":[{"key":"webgl_extensions","value":"ANGLE_instanced_arrays;EXT_blend_minmax;EXT_color_buffer_half_float;EXT_disjoint_timer_query;EXT_float_blend;EXT_frag_depth;EXT_shader_texture_lod;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_color_buffer_float;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw"},{"key":"webgl_extensions_hash","value":"35ad3898c88cfee4e1fa2c22596062e5"},{"key":"webgl_renderer","value":"WebKit WebGL"},{"key":"webgl_vendor","value":"WebKit"},{"key":"webgl_version","value":"WebGL 1.0 (OpenGL ES 2.0 Chromium)"},{"key":"webgl_shading_language_version","value":"WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)"},{"key":"webgl_aliased_line_width_range","value":"[1, 1]"},{"key":"webgl_aliased_point_size_range","value":"[1, 255.875]"},{"key":"webgl_antialiasing","value":"yes"},{"key":"webgl_bits","value":"8,8,24,8,8,0"},{"key":"webgl_max_params","value":"16,32,16384,1024,16384,16,16384,15,16,16,1024"},{"key":"webgl_max_viewport_dims","value":"[16384, 16384]"},{"key":"webgl_unmasked_vendor","value":"Google Inc. (Intel Inc.)"},{"key":"webgl_unmasked_renderer","value":"ANGLE (Intel Inc., Intel(R) UHD Graphics 630, OpenGL 4.1)"},{"key":"webgl_vsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_vsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_fsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_fsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_hash_webgl","value":"df7f80adde9b6d59d06605366db9e332"},{"key":"user_agent_data_brands","value":"Not.A/Brand,Chromium,Google Chrome"},{"key":"user_agent_data_mobile","value":false},{"key":"navigator_connection_downlink","value":1.45},{"key":"navigator_connection_downlink_max","value":null},{"key":"network_info_rtt","value":1050},{"key":"network_info_save_data","value":false},{"key":"network_info_rtt_type","value":null},{"key":"screen_pixel_depth","value":24},{"key":"navigator_device_memory","value":8},{"key":"navigator_languages","value":"zh-CN,zh,en"},{"key":"window_inner_width","value":0},{"key":"window_inner_height","value":0},{"key":"window_outer_width","value":1804},{"key":"window_outer_height","value":985},{"key":"browser_detection_firefox","value":false},{"key":"browser_detection_brave","value":false},{"key":"audio_codecs","value":"{\"ogg\":\"probably\",\"mp3\":\"probably\",\"wav\":\"probably\",\"m4a\":\"maybe\",\"aac\":\"probably\"}"},{"key":"video_codecs","value":"{\"ogg\":\"probably\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"\",\"mpeg4a\":\"\",\"theora\":\"\"}"},{"key":"media_query_dark_mode","value":true},{"key":"headless_browser_phantom","value":false},{"key":"headless_browser_selenium","value":false},{"key":"headless_browser_nightmare_js","value":false},{"key":"document__referrer","value":""},{"key":"window__ancestor_origins","value":["https://auth0.openai.com"]},{"key":"window__tree_index","value":[0]},{"key":"window__tree_structure","value":"[[]]"},{"key":"window__location_href","value":"https://tcr9i.chat.openai.com/v2/1.5.5/enforcement.fbfc14b0d793c6ef8359e0e4b4a91f67.html#0A1D34FC-659D-4E23-B17B-694DCFCF6A6C"},{"key":"client_config__sitedata_location_href","value":"https://auth0.openai.com/u/login/password"},{"key":"client_config__surl","value":"https://tcr9i.chat.openai.com"},{"key":"mobile_sdk__is_sdk"},{"key":"client_config__language","value":null},{"key":"navigator_battery_charging","value":true},{"key":"audio_fingerprint","value":"124.04347657808103"}]},{"key":"fe","value":["DNT:1","L:zh-CN","D:24","PR:2","S:1920,1080","AS:1920,985","TO:-480","SS:true","LS:true","IDB:true","B:false","ODB:true","CPUC:unknown","PK:MacIntel","CFP:344660654","FR:false","FOS:false","FB:false","JSF:Andale Mono,Arial,Arial Black,Arial Hebrew,Arial Narrow,Arial Rounded MT Bold,Arial Unicode MS,Comic Sans MS,Courier,Courier New,Geneva,Georgia,Helvetica,Helvetica Neue,Impact,LUCIDA GRANDE,Microsoft Sans Serif,Monaco,Palatino,Tahoma,Times,Times New Roman,Trebuchet MS,Verdana,Wingdings,Wingdings 2,Wingdings 3","P:Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,WebKit built-in PDF","T:0,false,false","H:20","SWF:false"]},{"key":"ife_hash","value":"503ef5d8117bf9668ad94ef3a442941a"},{"key":"cs","value":1},{"key":"jsbd","value":"{\"HL\":9,\"NCE\":true,\"DT\":\"\",\"NWD\":\"false\",\"DOTO\":1,\"DMTO\":1}"}]);
                    bx_json.to_string()
                }).await;
                get_auth0_from_bx(bx).await
            }
            Type::Platform => {
                let bx = PLATFORM_BX.get_or_init(||async {
                    let bx_json = serde_json::json!([{"key":"api_type","value":"js"},{"key":"p","value":1},{"key":"f","value":"05336d42f4eca6d43444241e3c5c367c"},{"key":"n","value":"MTY5NTM0MzU2MA=="},{"key":"wh","value":"04422442121a388db7bf68f6ce3ae8ca|72627afbfd19a741c7da1732218301ac"},{"key":"enhanced_fp","value":[{"key":"webgl_extensions","value":"ANGLE_instanced_arrays;EXT_blend_minmax;EXT_color_buffer_half_float;EXT_disjoint_timer_query;EXT_float_blend;EXT_frag_depth;EXT_shader_texture_lod;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_color_buffer_float;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw"},{"key":"webgl_extensions_hash","value":"35ad3898c88cfee4e1fa2c22596062e5"},{"key":"webgl_renderer","value":"WebKit WebGL"},{"key":"webgl_vendor","value":"WebKit"},{"key":"webgl_version","value":"WebGL 1.0 (OpenGL ES 2.0 Chromium)"},{"key":"webgl_shading_language_version","value":"WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)"},{"key":"webgl_aliased_line_width_range","value":"[1, 1]"},{"key":"webgl_aliased_point_size_range","value":"[1, 255.875]"},{"key":"webgl_antialiasing","value":"yes"},{"key":"webgl_bits","value":"8,8,24,8,8,0"},{"key":"webgl_max_params","value":"16,32,16384,1024,16384,16,16384,15,16,16,1024"},{"key":"webgl_max_viewport_dims","value":"[16384, 16384]"},{"key":"webgl_unmasked_vendor","value":"Google Inc. (Intel Inc.)"},{"key":"webgl_unmasked_renderer","value":"ANGLE (Intel Inc., Intel(R) UHD Graphics 630, OpenGL 4.1)"},{"key":"webgl_vsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_vsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_fsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_fsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_hash_webgl","value":"df7f80adde9b6d59d06605366db9e332"},{"key":"user_agent_data_brands","value":"Not.A/Brand,Chromium,Google Chrome"},{"key":"user_agent_data_mobile","value":false},{"key":"navigator_connection_downlink","value":1.0},{"key":"navigator_connection_downlink_max","value":null},{"key":"network_info_rtt","value":1050},{"key":"network_info_save_data","value":false},{"key":"network_info_rtt_type","value":null},{"key":"screen_pixel_depth","value":24},{"key":"navigator_device_memory","value":8},{"key":"navigator_languages","value":"zh-CN,zh,en"},{"key":"window_inner_width","value":0},{"key":"window_inner_height","value":0},{"key":"window_outer_width","value":1799},{"key":"window_outer_height","value":985},{"key":"browser_detection_firefox","value":false},{"key":"browser_detection_brave","value":false},{"key":"audio_codecs","value":"{\"ogg\":\"probably\",\"mp3\":\"probably\",\"wav\":\"probably\",\"m4a\":\"maybe\",\"aac\":\"probably\"}"},{"key":"video_codecs","value":"{\"ogg\":\"probably\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"\",\"mpeg4a\":\"\",\"theora\":\"\"}"},{"key":"media_query_dark_mode","value":true},{"key":"headless_browser_phantom","value":false},{"key":"headless_browser_selenium","value":false},{"key":"headless_browser_nightmare_js","value":false},{"key":"document__referrer","value":"https://platform.openai.com/"},{"key":"window__ancestor_origins","value":["https://platform.openai.com"]},{"key":"window__tree_index","value":[2]},{"key":"window__tree_structure","value":"[[],[[]],[]]"},{"key":"window__location_href","value":"https://openai-api.arkoselabs.com/v2/1.5.5/enforcement.fbfc14b0d793c6ef8359e0e4b4a91f67.html#23AAD243-4799-4A9E-B01D-1166C5DE02DF"},{"key":"client_config__sitedata_location_href","value":"https://platform.openai.com/account/api-keys"},{"key":"client_config__surl","value":"https://openai-api.arkoselabs.com"},{"key":"mobile_sdk__is_sdk"},{"key":"client_config__language","value":null},{"key":"navigator_battery_charging","value":true},{"key":"audio_fingerprint","value":"124.04347657808103"}]},{"key":"fe","value":["DNT:1","L:zh-CN","D:24","PR:3","S:1920,1080","AS:1920,985","TO:-480","SS:true","LS:true","IDB:true","B:false","ODB:true","CPUC:unknown","PK:MacIntel","CFP:344660654","FR:false","FOS:false","FB:false","JSF:","P:Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,WebKit built-in PDF","T:0,false,false","H:20","SWF:false"]},{"key":"ife_hash","value":"f24d62b6b6617ad8e309e1dc264906e0"},{"key":"cs","value":1},{"key":"jsbd","value":"{\"HL\":14,\"NCE\":true,\"DT\":\"\",\"NWD\":\"false\",\"DOTO\":1,\"DMTO\":1}"}]);
                    bx_json.to_string()
                }).await;
                get_platform_from_bx(bx).await
            }
        }
    }

    pub async fn new_from_bx(bx: &str, t: Type) -> anyhow::Result<Self> {
        match t {
            Type::Chat3 => get_chat3_from_bx(bx).await,
            Type::Chat4 => get_chat4_from_bx(bx).await,
            Type::Auth0 => get_auth0_from_bx(bx).await,
            Type::Platform => get_platform_from_bx(bx).await,
        }
    }

    /// Get ArkoseLabs token from context (Support ChatGPT, Platform, Auth)
    #[inline]
    pub async fn new_from_context(t: Type) -> anyhow::Result<Self> {
        get_from_context(t).await
    }

    /// Get ArkoseLabs token from HAR file (Support ChatGPT, Platform, Auth)
    #[inline]
    pub async fn new_from_har<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        get_from_har(path).await
    }
}

async fn get_chat3_from_bx(bx: &str) -> anyhow::Result<ArkoseToken> {
    get_from_bx_common(
        "tcr9i.chat.openai.com",
        bx,
        "3D86FBBA-9D22-402A-B512-3420086BA6CC",
        "https://chat.openai.com",
        "1.5.5",
        "inline",
    )
    .await
}

async fn get_chat4_from_bx(bx: &str) -> anyhow::Result<ArkoseToken> {
    get_from_bx_common(
        "tcr9i.chat.openai.com",
        bx,
        "35536E1E-65B4-4D96-9D97-6ADB7EFF8147",
        "https://chat.openai.com",
        "1.5.5",
        "lightbox",
    )
    .await
}

async fn get_auth0_from_bx(bx: &str) -> anyhow::Result<ArkoseToken> {
    get_from_bx_common(
        "tcr9i.chat.openai.com",
        bx,
        "0A1D34FC-659D-4E23-B17B-694DCFCF6A6C",
        "https://auth0.openai.com",
        "1.5.5",
        "lightbox",
    )
    .await
}

async fn get_platform_from_bx(bx: &str) -> anyhow::Result<ArkoseToken> {
    get_from_bx_common(
        "openai-api.arkoselabs.com",
        bx,
        "23AAD243-4799-4A9E-B01D-1166C5DE02DF",
        "https://platform.openai.com",
        "1.5.5",
        "lightbox",
    )
    .await
}

async fn get_from_bx_common(
    host: &str,
    bx: &str,
    public_key: &str,
    site: &str,
    capi_version: &str,
    capi_mode: &str,
) -> anyhow::Result<ArkoseToken> {
    let regex = REGEX
        .get_or_init(|| async {
            Regex::new(r#"\{"key":"n","value":"[^"]+"\}"#).expect("Invalid regex")
        })
        .await;
    let bv = HEADER_UA;
    let bt = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let bw = (bt - (bt % 21600)).to_string();
    let bx = regex.replace_all(
        bx,
        format!(
            r#"{{"key":"n","value":"{}"}}"#,
            general_purpose::STANDARD.encode(bt.to_string())
        ),
    );
    let bda = encrypt(&bx, &format!("{bv}{bw}"))?;

    let form: [(&str, &str); 8] = [
        (
            "bda",
            &base64::engine::general_purpose::STANDARD.encode(&bda),
        ),
        ("public_key", public_key),
        ("site", site),
        ("userbrowser", bv),
        ("capi_version", capi_version),
        ("capi_mode", capi_mode),
        ("style_theme", "default"),
        ("rnd", &(&rand::thread_rng().gen::<f64>().to_string())),
    ];

    let resp = context::get_instance()
        .client()
        .post(format!("https://{host}/fc/gt2/public_key/{public_key}"))
        .header(header::USER_AGENT, HEADER_UA)
        .header(header::ACCEPT, "*/*")
        .header(header::ACCEPT_ENCODING, "gzip, deflate, br")
        .header(header::ACCEPT_LANGUAGE, "zh-CN,zh-Hans;q=0.9")
        .header(header::HOST, host)
        .header("Sec-Fetch-Dest", "empty")
        .header("Sec-Fetch-Mode", "cors")
        .header("Sec-Fetch-Sitet", "same-origin")
        .form(&form)
        .send()
        .await?
        .error_for_status()?;

    Ok(resp.json::<ArkoseToken>().await?)
}

static REGEX: OnceCell<Regex> = OnceCell::const_new();

#[inline]
async fn get_from_har<P: AsRef<Path>>(path: P) -> anyhow::Result<ArkoseToken> {
    let regex = REGEX
        .get_or_init(|| async {
            Regex::new(r#"\{"key":"n","value":"[^"]+"\}"#).expect("Invalid regex")
        })
        .await;

    let mut entry = har::parse_from_file(path)?;

    let bt = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let bw = bt - (bt % 21600);
    let bv = &entry.bv;
    let bx = regex.replace_all(
        &entry.bx,
        format!(
            r#"{{"key":"n","value":"{}"}}"#,
            general_purpose::STANDARD.encode(bt.to_string())
        ),
    );
    let bda = crypto::encrypt(&bx, &format!("{bv}{bw}"))?;
    let rnd = format!("{}", rand::Rng::gen::<f64>(&mut rand::thread_rng()));

    entry
        .body
        .push_str(&format!("&bda={}", general_purpose::STANDARD.encode(&bda)));
    entry.body.push_str(&format!("&rnd={rnd}"));

    let client = context::get_instance().client();

    let method = Method::from_bytes(entry.method.as_bytes())?;

    let mut builder = client
        .request(method, entry.url)
        .timeout(std::time::Duration::from_secs(10));

    builder = builder.body(entry.body);

    for h in entry.headers.into_iter() {
        if h.name.eq_ignore_ascii_case("cookie") {
            let value = format!(
                "{};{}={}",
                h.value,
                generate_random_string(32),
                generate_random_string(32)
            );
            builder = builder.header(h.name, value);
            continue;
        }
        builder = builder.header(h.name, h.value)
    }

    let resp = builder.send().await?.error_for_status()?;
    Ok(resp.json::<ArkoseToken>().await?)
}

/// Get ArkoseLabs token from context (Only support ChatGPT, Platform, Auth)
#[inline]
async fn get_from_context(t: Type) -> anyhow::Result<ArkoseToken> {
    let valid_arkose_token = move |arkose_token: ArkoseToken| async {
        let get = move || async { Ok(arkose_token) };
        return submit_if_invalid(get).await;
    };

    let ctx = context::get_instance();

    let (state, file_path) = ctx.arkose_har_path(&t);
    if state {
        let arkose_token = ArkoseToken::new_from_har(file_path).await?;
        return valid_arkose_token(arkose_token).await;
    }

    if ctx.arkose_solver().is_some() {
        let arkose_token = ArkoseToken::new(t).await?;
        return valid_arkose_token(arkose_token).await;
    }

    anyhow::bail!("No solver available")
}

#[inline]
async fn submit_if_invalid<F, Fut>(get_token: F) -> anyhow::Result<ArkoseToken>
where
    F: FnOnce() -> Fut,
    Fut: futures_core::Future<Output = anyhow::Result<ArkoseToken>>,
{
    let ctx = context::get_instance();
    let arkose_token = get_token().await?;
    if arkose_token.success() {
        Ok(arkose_token)
    } else if let Some(arkose_solver) = ctx.arkose_solver() {
        submit_captcha(
            &arkose_solver.solver,
            &arkose_solver.client_key,
            arkose_token,
        )
        .await
    } else {
        anyhow::bail!("No solver available")
    }
}

#[inline]
async fn submit_captcha(
    solver: &'static Solver,
    key: &'static str,
    arkose_token: ArkoseToken,
) -> anyhow::Result<ArkoseToken> {
    let session = funcaptcha::start_challenge(arkose_token.value())
        .await
        .map_err(|error| anyhow::anyhow!("Error creating session: {error}"))?;

    let funs = anyhow::Context::context(session.funcaptcha(), "Valid funcaptcha error")?;
    let mut rx = match solver {
        Solver::Yescaptcha => {
            let (tx, rx) = tokio::sync::mpsc::channel(funs.len());
            for (i, fun) in funs.iter().enumerate() {
                let submit_task = SubmitSolver::builder()
                    .solved(solver)
                    .client_key(key)
                    .question(fun.instructions.clone())
                    .image(fun.image.clone())
                    .build();
                let sender = tx.clone();
                tokio::spawn(async move {
                    let res = funcaptcha::solver::submit_task(submit_task).await;
                    if let Some(err) = sender.send((i, res)).await.err() {
                        warn!("submit funcaptcha answer error: {err}")
                    }
                });
            }
            rx
        }
        Solver::Capsolver => {
            let mut classified_data = std::collections::HashMap::new();

            for item in funs.iter() {
                let question = item.game_variant.clone();
                classified_data
                    .entry(question)
                    .or_insert(Vec::new())
                    .push(item);
            }

            let (tx, rx) = tokio::sync::mpsc::channel(classified_data.len());

            for data in classified_data {
                let images_chunks = data
                    .1
                    .chunks(3)
                    .map(|item| item.iter().map(|item| item.image.clone()).collect())
                    .collect::<Vec<Vec<String>>>();

                for (i, images) in images_chunks.into_iter().enumerate() {
                    let submit_task = SubmitSolver::builder()
                        .solved(solver)
                        .client_key(key)
                        .question(data.0.clone())
                        .images(images)
                        .build();
                    let sender = tx.clone();
                    tokio::spawn(async move {
                        let res = funcaptcha::solver::submit_task(submit_task).await;
                        if let Some(err) = sender.send((i, res)).await.err() {
                            println!("submit funcaptcha answer error: {err}")
                        }
                    });
                }
            }
            rx
        }
    };

    // Wait for all tasks to complete
    let mut r = Vec::new();
    let mut mr = Vec::new();

    while let Some((i, res)) = rx.recv().await {
        let answers = res?;
        if answers.len() == 1 {
            r.push((i, answers[0]));
        } else {
            mr.push((i, answers));
        }
    }

    mr.sort_by_key(|&(i, _)| i);
    for (_, answers) in mr {
        for answer in answers {
            r.push((0, answer));
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
        Err(err) => anyhow::bail!("submit funcaptcha answer error: {err}"),
    };
}
