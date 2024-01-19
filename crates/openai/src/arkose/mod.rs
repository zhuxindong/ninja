mod blob;
pub mod crypto;
mod error;
pub mod funcaptcha;
pub mod har;
pub mod murmur;

use base64::engine::general_purpose;
use rand::thread_rng;
use serde::Serialize;
use std::path::Path;
use std::str::FromStr;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use base64::Engine;
use rand::Rng;
use regex::Regex;
use reqwest::header;
use reqwest::Method;
use serde::Deserialize;
use tokio::sync::OnceCell;

use self::funcaptcha::solver::ArkoseSolver;
use self::funcaptcha::solver::Solver;
use self::funcaptcha::solver::SubmitSolver;
use crate::arkose::crypto::encrypt;
use crate::debug;
use crate::generate_random_string;
use crate::gpt_model::GPTModel;
use crate::now_duration;
use crate::warn;
use crate::with_context;
use error::ArkoseError;

static REGEX: OnceCell<Regex> = OnceCell::const_new();
const GPT3_BX: &'static str = r#"[{"key":"api_type","value":"js"},{"key":"p","value":1},{"key":"f","value":"361215765a2ed02bf3f3c4e1a4f501a7"},{"key":"n","value":"MTY5ODEyMjE3MA=="},{"key":"wh","value":"9dff3eaaff9e5adc21363223db5d794e|1d99c2530fa1a96e676f9b1a1a9bcb58"},{"key":"enhanced_fp","value":[{"key":"webgl_extensions","value":"ANGLE_instanced_arrays;EXT_blend_minmax;EXT_color_buffer_half_float;EXT_float_blend;EXT_frag_depth;EXT_shader_texture_lod;EXT_texture_compression_bptc;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_color_buffer_float;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw"},{"key":"webgl_extensions_hash","value":"c70a87fa6fd567ea635c3a19c9f4c23a"},{"key":"webgl_renderer","value":"WebKit WebGL"},{"key":"webgl_vendor","value":"WebKit"},{"key":"webgl_version","value":"WebGL 1.0"},{"key":"webgl_shading_language_version","value":"WebGL GLSL ES 1.0 (1.0)"},{"key":"webgl_aliased_line_width_range","value":"[1, 1]"},{"key":"webgl_aliased_point_size_range","value":"[1, 511]"},{"key":"webgl_antialiasing","value":"yes"},{"key":"webgl_bits","value":"8,8,24,8,8,0"},{"key":"webgl_max_params","value":"16,32,16384,1024,16384,16,16384,30,16,16,1024"},{"key":"webgl_max_viewport_dims","value":"[16384, 16384]"},{"key":"webgl_unmasked_vendor","value":"Apple Inc."},{"key":"webgl_unmasked_renderer","value":"Apple GPU"},{"key":"webgl_vsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_vsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_fsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_fsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_hash_webgl","value":"3b034c93c1aa31e9cda3e5311c25db5e"},{"key":"user_agent_data_brands","value":null},{"key":"user_agent_data_mobile","value":null},{"key":"navigator_connection_downlink","value":null},{"key":"navigator_connection_downlink_max","value":null},{"key":"network_info_rtt","value":null},{"key":"network_info_save_data","value":null},{"key":"network_info_rtt_type","value":null},{"key":"screen_pixel_depth","value":24},{"key":"navigator_device_memory","value":null},{"key":"navigator_languages","value":"zh-CN"},{"key":"window_inner_width","value":0},{"key":"window_inner_height","value":0},{"key":"window_outer_width","value":1995},{"key":"window_outer_height","value":1344},{"key":"browser_detection_firefox","value":false},{"key":"browser_detection_brave","value":false},{"key":"audio_codecs","value":"{\"ogg\":\"\",\"mp3\":\"maybe\",\"wav\":\"\",\"m4a\":\"maybe\",\"aac\":\"maybe\"}"},{"key":"video_codecs","value":"{\"ogg\":\"\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"probably\",\"mpeg4a\":\"probably\",\"theora\":\"\"}"},{"key":"media_query_dark_mode","value":true},{"key":"headless_browser_phantom","value":false},{"key":"headless_browser_selenium","value":false},{"key":"headless_browser_nightmare_js","value":false},{"key":"document__referrer","value":""},{"key":"window__ancestor_origins","value":["https://chat.openai.com"]},{"key":"window__tree_index","value":[1]},{"key":"window__tree_structure","value":"[[],[]]"},{"key":"window__location_href","value":"https://tcr9i.chat.openai.com/v2/1.5.5/enforcement.fbfc14b0d793c6ef8359e0e4b4a91f67.html#3D86FBBA-9D22-402A-B512-3420086BA6CC"},{"key":"client_config__sitedata_location_href","value":"https://chat.openai.com/"},{"key":"client_config__surl","value":"https://tcr9i.chat.openai.com"},{"key":"mobile_sdk__is_sdk"},{"key":"client_config__language","value":null},{"key":"audio_fingerprint","value":"124.04345808873768"}]},{"key":"fe","value":["DNT:unknown","L:zh-CN","D:24","PR:1","S:2560,1440","AS:2560,1345","TO:-480","SS:true","LS:true","IDB:true","B:false","ODB:false","CPUC:unknown","PK:MacIntel","CFP:-432418192","FR:false","FOS:false","FB:false","JSF:Andale Mono,Arial,Arial Black,Arial Hebrew,Arial Narrow,Arial Rounded MT Bold,Arial Unicode MS,Comic Sans MS,Courier,Courier New,Geneva,Georgia,Helvetica,Helvetica Neue,Impact,LUCIDA GRANDE,Microsoft Sans Serif,Monaco,Palatino,Tahoma,Times,Times New Roman,Trebuchet MS,Verdana,Wingdings,Wingdings 2,Wingdings 3","P:Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,WebKit built-in PDF","T:0,false,false","H:8","SWF:false"]},{"key":"ife_hash","value":"a6c256ba86359de6e3b0b4ae46fe4b2a"},{"key":"cs","value":1},{"key":"jsbd","value":"{\"HL\":2,\"NCE\":true,\"DT\":\"\",\"NWD\":\"false\",\"DOTO\":1,\"DMTO\":1}"}]"#;
const GPT4_BX: &'static str = r#"[{"key":"api_type","value":"js"},{"key":"p","value":1},{"key":"f","value":"d4d8b12394eb4648003e079234035d42"},{"key":"n","value":"MTY5NDI3MDc2MA=="},{"key":"wh","value":"2fb296ec17ca939d0821cf36f562d695|72627afbfd19a741c7da1732218301ac"},{"key":"enhanced_fp","value":[{"key":"webgl_extensions","value":"ANGLE_instanced_arrays;EXT_blend_minmax;EXT_color_buffer_half_float;EXT_disjoint_timer_query;EXT_float_blend;EXT_frag_depth;EXT_shader_texture_lod;EXT_texture_compression_bptc;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_color_buffer_float;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw"},{"key":"webgl_extensions_hash","value":"58a5a04a5bef1a78fa88d5c5098bd237"},{"key":"webgl_renderer","value":"WebKit WebGL"},{"key":"webgl_vendor","value":"WebKit"},{"key":"webgl_version","value":"WebGL 1.0 (OpenGL ES 2.0 Chromium)"},{"key":"webgl_shading_language_version","value":"WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)"},{"key":"webgl_aliased_line_width_range","value":"[1, 1]"},{"key":"webgl_aliased_point_size_range","value":"[1, 511]"},{"key":"webgl_antialiasing","value":"yes"},{"key":"webgl_bits","value":"8,8,24,8,8,0"},{"key":"webgl_max_params","value":"16,32,16384,1024,16384,16,16384,30,16,16,1024"},{"key":"webgl_max_viewport_dims","value":"[16384, 16384]"},{"key":"webgl_unmasked_vendor","value":"Apple Inc."},{"key":"webgl_unmasked_renderer","value":"AMD Radeon Pro Vega 56 OpenGL Engine"},{"key":"webgl_vsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_vsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_fsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_fsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_hash_webgl","value":"47a905e57bc9a6076d887b0332318f20"},{"key":"user_agent_data_brands","value":"Chromium,Not)A;Brand,Google Chrome"},{"key":"user_agent_data_mobile","value":false},{"key":"navigator_connection_downlink","value":1.1},{"key":"navigator_connection_downlink_max","value":null},{"key":"network_info_rtt","value":650},{"key":"network_info_save_data","value":false},{"key":"network_info_rtt_type","value":null},{"key":"screen_pixel_depth","value":24},{"key":"navigator_device_memory","value":4},{"key":"navigator_languages","value":"en-US,en"},{"key":"window_inner_width","value":0},{"key":"window_inner_height","value":0},{"key":"window_outer_width","value":1944},{"key":"window_outer_height","value":1301},{"key":"browser_detection_firefox","value":false},{"key":"browser_detection_brave","value":false},{"key":"audio_codecs","value":"{\"ogg\":\"probably\",\"mp3\":\"probably\",\"wav\":\"probably\",\"m4a\":\"maybe\",\"aac\":\"probably\"}"},{"key":"video_codecs","value":"{\"ogg\":\"probably\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"\",\"mpeg4a\":\"\",\"theora\":\"\"}"},{"key":"media_query_dark_mode","value":true},{"key":"headless_browser_phantom","value":false},{"key":"headless_browser_selenium","value":false},{"key":"headless_browser_nightmare_js","value":false},{"key":"document__referrer","value":"http://127.0.0.1:8000/"},{"key":"window__ancestor_origins","value":["https://chat.openai.com"]},{"key":"window__tree_index","value":[1]},{"key":"window__tree_structure","value":"[[],[]]"},{"key":"window__location_href","value":"https://tcr9i.chat.openai.com/v2/1.5.5/enforcement.fbfc14b0d793c6ef8359e0e4b4a91f67.html#35536E1E-65B4-4D96-9D97-6ADB7EFF8147"},{"key":"client_config__sitedata_location_href","value":"https://chat.openai.com/"},{"key":"client_config__surl","value":"https://tcr9i.chat.openai.com"},{"key":"mobile_sdk__is_sdk"},{"key":"client_config__language","value":null},{"key":"navigator_battery_charging","value":true},{"key":"audio_fingerprint","value":"124.04347651847638"}]},{"key":"fe","value":["DNT:unknown","L:en-US","D:24","PR:1","S:2560,1440","AS:2560,1345","TO:420","SS:true","LS:true","IDB:true","B:false","ODB:true","CPUC:unknown","PK:MacIntel","CFP:1855649544","FR:false","FOS:false","FB:false","JSF:","P:Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,WebKit built-in PDF","T:0,false,false","H:8","SWF:false"]},{"key":"ife_hash","value":"fa35325a5718d9a235c3a4aa060dc33b"},{"key":"cs","value":1},{"key":"jsbd","value":"{\"HL\":13,\"NCE\":true,\"DT\":\"\",\"NWD\":\"false\",\"DOTO\":1,\"DMTO\":1}"}]"#;
const AUTH_BX: &'static str = r#"[{"key":"api_type","value":"js"},{"key":"p","value":1},{"key":"f","value":"fc7e35accfb122a7dd6099148ce96917"},{"key":"n","value":"MTY5NTcwMjYyNw=="},{"key":"wh","value":"04422442121a388db7bf68f6ce3ae8ca|72627afbfd19a741c7da1732218301ac"},{"key":"enhanced_fp","value":[{"key":"webgl_extensions","value":"ANGLE_instanced_arrays;EXT_blend_minmax;EXT_color_buffer_half_float;EXT_disjoint_timer_query;EXT_float_blend;EXT_frag_depth;EXT_shader_texture_lod;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_color_buffer_float;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw"},{"key":"webgl_extensions_hash","value":"35ad3898c88cfee4e1fa2c22596062e5"},{"key":"webgl_renderer","value":"WebKit WebGL"},{"key":"webgl_vendor","value":"WebKit"},{"key":"webgl_version","value":"WebGL 1.0 (OpenGL ES 2.0 Chromium)"},{"key":"webgl_shading_language_version","value":"WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)"},{"key":"webgl_aliased_line_width_range","value":"[1, 1]"},{"key":"webgl_aliased_point_size_range","value":"[1, 255.875]"},{"key":"webgl_antialiasing","value":"yes"},{"key":"webgl_bits","value":"8,8,24,8,8,0"},{"key":"webgl_max_params","value":"16,32,16384,1024,16384,16,16384,15,16,16,1024"},{"key":"webgl_max_viewport_dims","value":"[16384, 16384]"},{"key":"webgl_unmasked_vendor","value":"Google Inc. (Intel Inc.)"},{"key":"webgl_unmasked_renderer","value":"ANGLE (Intel Inc., Intel(R) UHD Graphics 630, OpenGL 4.1)"},{"key":"webgl_vsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_vsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_fsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_fsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_hash_webgl","value":"df7f80adde9b6d59d06605366db9e332"},{"key":"user_agent_data_brands","value":"Not.A/Brand,Chromium,Google Chrome"},{"key":"user_agent_data_mobile","value":false},{"key":"navigator_connection_downlink","value":1.45},{"key":"navigator_connection_downlink_max","value":null},{"key":"network_info_rtt","value":1050},{"key":"network_info_save_data","value":false},{"key":"network_info_rtt_type","value":null},{"key":"screen_pixel_depth","value":24},{"key":"navigator_device_memory","value":8},{"key":"navigator_languages","value":"zh-CN,zh,en"},{"key":"window_inner_width","value":0},{"key":"window_inner_height","value":0},{"key":"window_outer_width","value":1804},{"key":"window_outer_height","value":985},{"key":"browser_detection_firefox","value":false},{"key":"browser_detection_brave","value":false},{"key":"audio_codecs","value":"{\"ogg\":\"probably\",\"mp3\":\"probably\",\"wav\":\"probably\",\"m4a\":\"maybe\",\"aac\":\"probably\"}"},{"key":"video_codecs","value":"{\"ogg\":\"probably\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"\",\"mpeg4a\":\"\",\"theora\":\"\"}"},{"key":"media_query_dark_mode","value":true},{"key":"headless_browser_phantom","value":false},{"key":"headless_browser_selenium","value":false},{"key":"headless_browser_nightmare_js","value":false},{"key":"document__referrer","value":""},{"key":"window__ancestor_origins","value":["https://auth0.openai.com"]},{"key":"window__tree_index","value":[0]},{"key":"window__tree_structure","value":"[[]]"},{"key":"window__location_href","value":"https://tcr9i.chat.openai.com/v2/1.5.5/enforcement.fbfc14b0d793c6ef8359e0e4b4a91f67.html#0A1D34FC-659D-4E23-B17B-694DCFCF6A6C"},{"key":"client_config__sitedata_location_href","value":"https://auth0.openai.com/u/login/password"},{"key":"client_config__surl","value":"https://tcr9i.chat.openai.com"},{"key":"mobile_sdk__is_sdk"},{"key":"client_config__language","value":null},{"key":"navigator_battery_charging","value":true},{"key":"audio_fingerprint","value":"124.04347657808103"}]},{"key":"fe","value":["DNT:1","L:zh-CN","D:24","PR:2","S:1920,1080","AS:1920,985","TO:-480","SS:true","LS:true","IDB:true","B:false","ODB:true","CPUC:unknown","PK:MacIntel","CFP:344660654","FR:false","FOS:false","FB:false","JSF:Andale Mono,Arial,Arial Black,Arial Hebrew,Arial Narrow,Arial Rounded MT Bold,Arial Unicode MS,Comic Sans MS,Courier,Courier New,Geneva,Georgia,Helvetica,Helvetica Neue,Impact,LUCIDA GRANDE,Microsoft Sans Serif,Monaco,Palatino,Tahoma,Times,Times New Roman,Trebuchet MS,Verdana,Wingdings,Wingdings 2,Wingdings 3","P:Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,WebKit built-in PDF","T:0,false,false","H:20","SWF:false"]},{"key":"ife_hash","value":"503ef5d8117bf9668ad94ef3a442941a"},{"key":"cs","value":1},{"key":"jsbd","value":"{\"HL\":9,\"NCE\":true,\"DT\":\"\",\"NWD\":\"false\",\"DOTO\":1,\"DMTO\":1}"}]"#;
const PLATFORM_BX: &'static str = r#"[{"key":"api_type","value":"js"},{"key":"p","value":1},{"key":"f","value":"05336d42f4eca6d43444241e3c5c367c"},{"key":"n","value":"MTY5NTM0MzU2MA=="},{"key":"wh","value":"04422442121a388db7bf68f6ce3ae8ca|72627afbfd19a741c7da1732218301ac"},{"key":"enhanced_fp","value":[{"key":"webgl_extensions","value":"ANGLE_instanced_arrays;EXT_blend_minmax;EXT_color_buffer_half_float;EXT_disjoint_timer_query;EXT_float_blend;EXT_frag_depth;EXT_shader_texture_lod;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_color_buffer_float;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw"},{"key":"webgl_extensions_hash","value":"35ad3898c88cfee4e1fa2c22596062e5"},{"key":"webgl_renderer","value":"WebKit WebGL"},{"key":"webgl_vendor","value":"WebKit"},{"key":"webgl_version","value":"WebGL 1.0 (OpenGL ES 2.0 Chromium)"},{"key":"webgl_shading_language_version","value":"WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)"},{"key":"webgl_aliased_line_width_range","value":"[1, 1]"},{"key":"webgl_aliased_point_size_range","value":"[1, 255.875]"},{"key":"webgl_antialiasing","value":"yes"},{"key":"webgl_bits","value":"8,8,24,8,8,0"},{"key":"webgl_max_params","value":"16,32,16384,1024,16384,16,16384,15,16,16,1024"},{"key":"webgl_max_viewport_dims","value":"[16384, 16384]"},{"key":"webgl_unmasked_vendor","value":"Google Inc. (Intel Inc.)"},{"key":"webgl_unmasked_renderer","value":"ANGLE (Intel Inc., Intel(R) UHD Graphics 630, OpenGL 4.1)"},{"key":"webgl_vsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_vsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_fsf_params","value":"23,127,127,23,127,127,23,127,127"},{"key":"webgl_fsi_params","value":"0,31,30,0,31,30,0,31,30"},{"key":"webgl_hash_webgl","value":"df7f80adde9b6d59d06605366db9e332"},{"key":"user_agent_data_brands","value":"Not.A/Brand,Chromium,Google Chrome"},{"key":"user_agent_data_mobile","value":false},{"key":"navigator_connection_downlink","value":1.0},{"key":"navigator_connection_downlink_max","value":null},{"key":"network_info_rtt","value":1050},{"key":"network_info_save_data","value":false},{"key":"network_info_rtt_type","value":null},{"key":"screen_pixel_depth","value":24},{"key":"navigator_device_memory","value":8},{"key":"navigator_languages","value":"zh-CN,zh,en"},{"key":"window_inner_width","value":0},{"key":"window_inner_height","value":0},{"key":"window_outer_width","value":1799},{"key":"window_outer_height","value":985},{"key":"browser_detection_firefox","value":false},{"key":"browser_detection_brave","value":false},{"key":"audio_codecs","value":"{\"ogg\":\"probably\",\"mp3\":\"probably\",\"wav\":\"probably\",\"m4a\":\"maybe\",\"aac\":\"probably\"}"},{"key":"video_codecs","value":"{\"ogg\":\"probably\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"\",\"mpeg4a\":\"\",\"theora\":\"\"}"},{"key":"media_query_dark_mode","value":true},{"key":"headless_browser_phantom","value":false},{"key":"headless_browser_selenium","value":false},{"key":"headless_browser_nightmare_js","value":false},{"key":"document__referrer","value":"https://platform.openai.com/"},{"key":"window__ancestor_origins","value":["https://platform.openai.com"]},{"key":"window__tree_index","value":[2]},{"key":"window__tree_structure","value":"[[],[[]],[]]"},{"key":"window__location_href","value":"https://openai-api.arkoselabs.com/v2/1.5.5/enforcement.fbfc14b0d793c6ef8359e0e4b4a91f67.html#23AAD243-4799-4A9E-B01D-1166C5DE02DF"},{"key":"client_config__sitedata_location_href","value":"https://platform.openai.com/account/api-keys"},{"key":"client_config__surl","value":"https://openai-api.arkoselabs.com"},{"key":"mobile_sdk__is_sdk"},{"key":"client_config__language","value":null},{"key":"navigator_battery_charging","value":true},{"key":"audio_fingerprint","value":"124.04347657808103"}]},{"key":"fe","value":["DNT:1","L:zh-CN","D:24","PR:3","S:1920,1080","AS:1920,985","TO:-480","SS:true","LS:true","IDB:true","B:false","ODB:true","CPUC:unknown","PK:MacIntel","CFP:344660654","FR:false","FOS:false","FB:false","JSF:","P:Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,WebKit built-in PDF","T:0,false,false","H:20","SWF:false"]},{"key":"ife_hash","value":"f24d62b6b6617ad8e309e1dc264906e0"},{"key":"cs","value":1},{"key":"jsbd","value":"{\"HL\":14,\"NCE\":true,\"DT\":\"\",\"NWD\":\"false\",\"DOTO\":1,\"DMTO\":1}"}]"#;

#[derive(Hash, PartialEq, Eq, Debug, Clone)]
pub enum Type {
    GPT3,
    GPT4,
    Auth,
    SignUp,
    Platform,
}

impl Type {
    pub fn from_pk(pk: &str) -> anyhow::Result<Self> {
        let typed = match pk {
            "3D86FBBA-9D22-402A-B512-3420086BA6CC" => Type::GPT3,
            "35536E1E-65B4-4D96-9D97-6ADB7EFF8147" => Type::GPT4,
            "0A1D34FC-659D-4E23-B17B-694DCFCF6A6C" => Type::Auth,
            "0655BC92-82E1-43D9-B32E-9DF9B01AF50C" => Type::SignUp,
            "23AAD243-4799-4A9E-B01D-1166C5DE02DF" => Type::Platform,
            _ => anyhow::bail!(ArkoseError::InvalidPublicKey(pk.to_owned())),
        };
        Ok(typed)
    }

    pub fn get_site(&self) -> &'static str {
        match self {
            Type::GPT3 | Type::GPT4 => "https://chat.openai.com",
            Type::Platform | Type::SignUp => "https://platform.openai.com",
            Type::Auth => "https://auth0.openai.com",
        }
    }
}

impl From<GPTModel> for Type {
    fn from(value: GPTModel) -> Self {
        match value {
            GPTModel::Gpt35 => Type::GPT3,
            GPTModel::Gpt4 | GPTModel::Gpt4Mobile => Type::GPT4,
        }
    }
}

impl FromStr for Type {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "gpt3" => Ok(Type::GPT3),
            "gpt4" => Ok(Type::GPT4),
            "auth" => Ok(Type::Auth),
            "platform" => Ok(Type::Platform),
            _ => anyhow::bail!(ArkoseError::InvalidPlatformType(s.to_owned())),
        }
    }
}

/// curl 'https://tcr9i.chat.openai.com/fc/gt2/public_key/35536E1E-65B4-4D96-9D97-6ADB7EFF8147' --data-raw 'public_key=35536E1E-65B4-4D96-9D97-6ADB7EFF8147'
#[derive(Serialize, Deserialize, Debug)]
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

impl Into<String> for ArkoseToken {
    fn into(self) -> String {
        self.token
    }
}

impl ArkoseToken {
    /// Get ArkoseLabs token
    pub fn value(&self) -> &str {
        &self.token
    }

    /// Check if the token is valid
    pub fn success(&self) -> bool {
        self.token.contains("sup=1")
    }

    #[inline]
    pub async fn new(typed: Type, identifier: Option<String>) -> anyhow::Result<Self> {
        match typed {
            Type::GPT3 => {
                get_from_bx_common(
                    "tcr9i.chat.openai.com",
                    GPT3_BX,
                    "3D86FBBA-9D22-402A-B512-3420086BA6CC",
                    "https://chat.openai.com",
                    "1.5.5",
                    "inline",
                    identifier,
                )
                .await
            }
            Type::GPT4 => {
                get_from_bx_common(
                    "tcr9i.chat.openai.com",
                    GPT4_BX,
                    "35536E1E-65B4-4D96-9D97-6ADB7EFF8147",
                    "https://chat.openai.com",
                    "1.5.5",
                    "lightbox",
                    identifier,
                )
                .await
            }
            Type::Auth => {
                get_from_bx_common(
                    "tcr9i.chat.openai.com",
                    AUTH_BX,
                    "0A1D34FC-659D-4E23-B17B-694DCFCF6A6C",
                    "https://auth0.openai.com",
                    "1.5.5",
                    "lightbox",
                    identifier,
                )
                .await
            }
            Type::SignUp => {
                get_from_bx_common(
                    "openai-api.arkoselabs.com",
                    PLATFORM_BX,
                    "0655BC92-82E1-43D9-B32E-9DF9B01AF50C",
                    "https://platform.openai.com",
                    "2.3.1",
                    "lightbox",
                    identifier,
                )
                .await
            }
            Type::Platform => {
                get_from_bx_common(
                    "openai-api.arkoselabs.com",
                    PLATFORM_BX,
                    "23AAD243-4799-4A9E-B01D-1166C5DE02DF",
                    "https://platform.openai.com",
                    "1.5.5",
                    "lightbox",
                    identifier,
                )
                .await
            }
        }
    }

    /// Get ArkoseLabs token from context (Support ChatGPT, Platform, Auth)
    #[inline]
    pub async fn new_from_context(typed: Type, identifier: Option<String>) -> anyhow::Result<Self> {
        // If enable gpt3 arkoselabs experiment
        if typed.eq(&Type::GPT3)
            && with_context!(arkose_gpt3_experiment)
            && !with_context!(arkose_gpt3_experiment_solver)
        {
            use rand::distributions::Alphanumeric;

            let mut rng = thread_rng();

            let before_dot: String = (0..18)
                .map(|_| rng.sample(Alphanumeric))
                .map(char::from)
                .collect();

            let after_dot: String = (0..10)
                .map(|_| rng.sample(Alphanumeric))
                .map(char::from)
                .collect();

            let rid = rng.gen_range(1..=99);
            // experiment token
            let fake_token = format!("{before_dot}.{after_dot}|r=us-west-2|meta=3|metabgclr=transparent|metaiconclr=%23757575|guitextcolor=%23000000|pk=35536E1E-65B4-4D96-9D97-6ADB7EFF8147|at=40|sup=1|rid={rid}|ag=101|cdn_url=https%3A%2F%2Ftcr9i.chat.openai.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-us-west-2.arkoselabs.com|surl=https%3A%2F%2Ftcr9i.chat.openai.com|smurl=https%3A%2F%2Ftcr9i.chat.openai.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager");
            return Ok(ArkoseToken::from(fake_token));
        }

        // Get arkose solver
        let arkose_solver = with_context!(arkose_solver);

        // If har path is not empty, use har file
        if let Some(file_path) = with_context!(arkose_har_path, &typed).file_path {
            let arkose_token = ArkoseToken::new_from_har(&file_path, identifier).await?;
            return valid_arkose_token(arkose_token, arkose_solver).await;
        }

        // If arkose solver is not empty, use bx
        if arkose_solver.is_some() {
            let arkose_token = ArkoseToken::new(typed.clone(), identifier).await?;
            return valid_arkose_token(arkose_token, arkose_solver).await;
        }

        anyhow::bail!(ArkoseError::NoSolverAvailable)
    }

    /// Get ArkoseLabs token from HAR file (Support ChatGPT, Platform, Auth)
    #[inline]
    pub async fn new_from_har<P: AsRef<Path>>(
        path: P,
        identifier: Option<String>,
    ) -> anyhow::Result<Self> {
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

        // Update bda entry
        entry.body.push_str(&format!(
            "&bda={}",
            general_purpose::STANDARD.encode(&crypto::encrypt(&bx, &format!("{bv}{bw}"))?)
        ));

        // Update rnd entry
        entry.body.push_str(&format!(
            "&rnd={}",
            rand::Rng::gen::<f64>(&mut rand::thread_rng())
        ));

        // If identifier is not empty, get blob
        if let Ok(Some(blob)) = blob::get_blob(entry.typed, identifier).await {
            entry.body.push_str(&format!("&data[blob]={blob}"));
        }

        let mut builder = with_context!(arkose_client)
            .request(Method::from_bytes(entry.method.as_bytes())?, entry.url)
            .timeout(std::time::Duration::from_secs(10))
            .body(entry.body);

        for h in entry.headers.into_iter() {
            if h.name.eq_ignore_ascii_case("cookie") {
                let value = format!(
                    "{};{}={}",
                    h.value,
                    generate_random_string(16),
                    generate_random_string(96)
                );
                builder = builder.header(h.name, value);
                continue;
            }
            builder = builder.header(h.name, h.value)
        }

        Ok(builder
            .send()
            .await?
            .error_for_status()?
            .json::<ArkoseToken>()
            .await?)
    }

    /// Callback to arkose
    #[inline]
    pub async fn callback(&self) -> anyhow::Result<()> {
        // Split the data string by the "|" delimiter
        let elements: Vec<&str> = self.token.split('|').collect();

        // Session token
        let session_token = elements
            .first()
            .ok_or_else(|| ArkoseError::InvalidArkoseToken(self.token.to_owned()))?
            .to_string();

        // Create a mutable HashMap to store the key-value pairs
        let mut parsed_data = std::collections::HashMap::new();

        for element in elements {
            let key_value: Vec<&str> = element.splitn(2, '=').collect();

            if key_value.len() == 2 {
                let key = key_value[0];
                let value = key_value[1];
                // Insert the key-value pair into the HashMap
                parsed_data.insert(key, value);
            }
        }

        let mut callback_data = Vec::with_capacity(6);
        callback_data.push(format!("callback=__jsonp_{}", now_duration()?.as_millis()));
        callback_data.push(format!("category=loaded"));
        callback_data.push(format!("action=game loaded"));
        callback_data.push(format!("session_token={session_token}"));
        // Print the parsed data
        for (key, value) in parsed_data {
            if key.eq("pk") {
                callback_data.push(format!("data[public_key]={value}"));
                let typed = Type::from_pk(value)?;
                callback_data.push(format!("data[site]={}", typed.get_site()));
            }
        }

        let callback_query = callback_data.join("&");

        let resp = with_context!(arkose_client)
            .get(format!(
                "https://client-api.arkoselabs.com/fc/a/?{callback_query}"
            ))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await?;

        match resp.error_for_status() {
            Ok(resp) => {
                if tracing::event_enabled!(tracing::Level::DEBUG) {
                    let text = resp.text().await?;
                    debug!("funcaptcha callback: {text}")
                }
            }
            Err(err) => {
                warn!("funcaptcha callback error: {err}")
            }
        }

        Ok(())
    }
}

async fn get_from_bx_common(
    host: &str,
    bx: &str,
    public_key: &str,
    site: &str,
    capi_version: &str,
    capi_mode: &str,
    identifier: Option<String>,
) -> anyhow::Result<ArkoseToken> {
    let regex = REGEX
        .get_or_init(|| async {
            Regex::new(r#"\{"key":"n","value":"[^"]+"\}"#).expect("Invalid regex")
        })
        .await;
    let bv = "okhttp/4.9.1";
    let bt = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let bw = (bt - (bt % 21600)).to_string();
    let bx = regex.replace_all(
        bx,
        format!(
            r#"{{"key":"n","value":"{}"}}"#,
            general_purpose::STANDARD.encode(bt.to_string())
        ),
    );

    let mut form = vec![
        (
            "bda",
            base64::engine::general_purpose::STANDARD.encode(&encrypt(&bx, &format!("{bv}{bw}"))?),
        ),
        ("public_key", public_key.to_owned()),
        ("site", site.to_owned()),
        ("userbrowser", bv.to_owned()),
        ("capi_version", capi_version.to_owned()),
        ("capi_mode", capi_mode.to_owned()),
        ("style_theme", "default".to_owned()),
        ("rnd", rand::thread_rng().gen::<f64>().to_string()),
    ];

    // If identifier is not empty, get blob
    if let Ok(Some(blob)) = blob::get_blob(Type::from_pk(public_key)?, identifier).await {
        form.push(("data[blob]", blob));
    }

    let resp = with_context!(arkose_client)
        .post(format!("https://{host}/fc/gt2/public_key/{public_key}"))
        .header(header::USER_AGENT, "okhttp/4.9.1")
        .header(header::ACCEPT, "*/*")
        .header(header::ACCEPT_ENCODING, "gzip, deflate, br")
        .header(header::ACCEPT_LANGUAGE, "zh-CN,zh-Hans;q=0.9")
        .header(header::HOST, host)
        .header(header::ORIGIN, site)
        .header("Sec-Fetch-Dest", "empty")
        .header("Sec-Fetch-Mode", "cors")
        .header("Sec-Fetch-Sitet", "same-origin")
        .form(&form)
        .send()
        .await?
        .error_for_status()?;

    Ok(resp.json::<ArkoseToken>().await?)
}

async fn valid_arkose_token(
    arkose_token: ArkoseToken,
    arkose_solver: Option<&'static ArkoseSolver>,
) -> anyhow::Result<ArkoseToken>
where
{
    if arkose_token.success() {
        // Submit token to funcaptcha callback
        let _ = arkose_token.callback().await;
    } else {
        // If arkose solver is not empty, use solver
        if let Some(arkose_solver) = arkose_solver {
            return submit_captcha(
                &arkose_solver.solver,
                &arkose_solver.client_key,
                arkose_token,
            )
            .await;
        }
        warn!("arkose token is invalid, but no solver is available.")
    }

    Ok(arkose_token)
}

async fn submit_captcha(
    solver: &'static Solver,
    key: &'static str,
    arkose_token: ArkoseToken,
) -> anyhow::Result<ArkoseToken> {
    let session = funcaptcha::start_challenge(&arkose_token)
        .await
        .map_err(ArkoseError::CreateSessionError)?;

    let funs = session.funcaptcha().ok_or(ArkoseError::InvalidFunCaptcha)?;
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
                            warn!("submit funcaptcha answer error: {err}")
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

    // Get answers
    while let Some((i, res)) = rx.recv().await {
        let answers = res?;
        if answers.len() == 1 {
            r.push((i, answers[0]));
        } else {
            mr.push((i, answers));
        }
    }

    // Sort by vec index
    mr.sort_by_key(|&(i, _)| i);
    for (_, answers) in mr {
        for answer in answers {
            r.push((0, answer));
        }
    }
    // Sort by index
    r.sort_by_key(|&(i, _)| i);

    // Convert to answers
    let answers = r
        .into_iter()
        .map(|(_, answer)| answer)
        .collect::<Vec<i32>>();

    // Submit answers
    return match session.submit_answer(answers).await {
        Ok(_) => {
            let new_token = arkose_token.value().replace("at=40", "at=40|sup=1");
            Ok(ArkoseToken::from(new_token))
        }
        Err(err) => anyhow::bail!(ArkoseError::SubmitAnswerError(err)),
    };
}
