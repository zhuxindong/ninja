use crate::store::{conf::Conf, Store};
use inquire::{CustomType, Text};

use super::{
    context::Context,
    render_config,
    valid::{valid_file_path, valid_url},
};

pub(super) async fn config_prompt() -> anyhow::Result<()> {
    let store = Context::get_conf_store().await;
    let mut conf = store.get(Conf::default())?.unwrap_or(Conf::default());
    let mut official_api = Text::new("Official API prefix ›")
        .with_render_config(render_config())
        .with_help_message("Example: https://example.com")
        .with_validator(valid_url);
    if let Some(content) = conf.official_api.as_deref() {
        if !content.is_empty() {
            official_api = official_api.with_initial_value(content)
        }
    }

    let mut unofficial_api = Text::new("Unofficial API prefix ›")
        .with_render_config(render_config())
        .with_help_message("Example: https://example.com")
        .with_validator(valid_url);
    if let Some(content) = conf.unofficial_api.as_deref() {
        if !content.is_empty() {
            unofficial_api = unofficial_api.with_initial_value(content)
        }
    };

    let mut proxy = Text::new("Proxy ›")
        .with_render_config(render_config())
        .with_help_message("Example: https://example.com")
        .with_validator(valid_url);
    if let Some(content) = conf.proxy.as_deref() {
        if !content.is_empty() {
            proxy = proxy.with_initial_value(content)
        }
    };

    let mut arkose_har_path = Text::new("Arkose HAR path ›")
        .with_render_config(render_config())
        .with_help_message("About the browser HAR file path requested by ArkoseLabs")
        .with_validator(valid_file_path);
    if let Some(content) = conf.arkose_har_path.as_deref() {
        arkose_har_path = arkose_har_path.with_initial_value(content)
    };

    let mut arkose_yescaptcha_key = Text::new("Arkose YesCaptcha key ›")
        .with_render_config(render_config())
        .with_help_message("About the YesCaptcha platform client key solved by ArkoseLabs");
    if let Some(content) = conf.arkose_yescaptcha_key.as_deref() {
        arkose_yescaptcha_key = arkose_yescaptcha_key.with_initial_value(content)
    };

    let mut arkose_token_endpoint = Text::new("Arkose token endpoint ›")
        .with_render_config(render_config())
        .with_help_message("Example: https://example.com")
        .with_validator(valid_url);
    if let Some(content) = conf.arkose_token_endpoint.as_deref() {
        arkose_token_endpoint = arkose_token_endpoint.with_initial_value(content)
    };

    conf.official_api = official_api.prompt_skippable()?.filter(|s| !s.is_empty());
    conf.unofficial_api = unofficial_api.prompt_skippable()?.filter(|s| !s.is_empty());
    conf.proxy = proxy.prompt_skippable()?.filter(|s| !s.is_empty());
    conf.arkose_har_path = arkose_har_path
        .prompt_skippable()?
        .filter(|s| !s.is_empty());
    conf.arkose_yescaptcha_key = arkose_yescaptcha_key
        .prompt_skippable()?
        .filter(|s| !s.is_empty());
    conf.arkose_token_endpoint = arkose_token_endpoint
        .prompt_skippable()?
        .filter(|s| !s.is_empty());

    let timeout = CustomType::<usize>::new("Client timeout (seconds) ›")
        .with_render_config(render_config())
        .with_formatter(&|i| format!("${i:.2}"))
        .with_error_message("Please type a valid number")
        .with_default(conf.timeout)
        .prompt_skippable()?;

    let connect_timeout = CustomType::<usize>::new("Client connect timeout (seconds) ›")
        .with_render_config(render_config())
        .with_formatter(&|i| format!("${i:.2}"))
        .with_error_message("Please type a valid number")
        .with_default(conf.connect_timeout)
        .prompt_skippable()?;

    let tcp_keepalive = CustomType::<usize>::new("TCP keepalive (seconds) ›")
        .with_render_config(render_config())
        .with_formatter(&|i| format!("${i:.2}"))
        .with_error_message("Please type a valid number")
        .with_default(conf.tcp_keepalive)
        .prompt_skippable()?;

    if let Some(timeout) = timeout {
        conf.timeout = timeout;
    }

    if let Some(connect_timeout) = connect_timeout {
        conf.connect_timeout = connect_timeout;
    }

    if let Some(tcp_keepalive) = tcp_keepalive {
        conf.tcp_keepalive = tcp_keepalive;
    }

    store.add(conf)?;

    Ok(())
}
