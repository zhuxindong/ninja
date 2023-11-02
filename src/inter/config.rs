use crate::inter::valid::valid_solver;
use crate::store::{conf::Conf, Store};
use inquire::{Confirm, CustomType, Text};
use openai::arkose::funcaptcha::Solver;

use super::{
    context::Context,
    render_config,
    valid::{valid_file_path, valid_url},
};

pub async fn prompt() -> anyhow::Result<()> {
    let ans = Confirm::new("Are you sure you want to change the configuration?")
        .with_default(false)
        .prompt_skippable()?;

    if ans.is_none() || !ans.unwrap_or_default() {
        return Ok(());
    }

    let store = Context::get_conf_store().await;
    let mut conf = store.read(Conf::new())?.unwrap_or(Conf::new());
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
        .with_help_message("Supports http, https, socks5")
        .with_validator(valid_url);
    if let Some(content) = conf.proxy.as_deref() {
        if !content.is_empty() {
            proxy = proxy.with_initial_value(content)
        }
    };

    let mut arkose_chat_har_file = Text::new("ChatGPT ArkoseLabs HAR file ›")
        .with_render_config(render_config())
        .with_help_message("About the browser HAR file path requested by ChatGPT ArkoseLabs")
        .with_validator(valid_file_path);
    if let Some(content) = conf.arkose_chat_har_path.as_deref() {
        arkose_chat_har_file = arkose_chat_har_file.with_initial_value(content)
    };

    let mut arkose_auth_har_path = Text::new("Auth ArkoseLabs HAR file ›")
        .with_render_config(render_config())
        .with_help_message("About the browser HAR file path requested by Auth ArkoseLabs")
        .with_validator(valid_file_path);
    if let Some(content) = conf.arkose_auth_har_path.as_deref() {
        arkose_auth_har_path = arkose_auth_har_path.with_initial_value(content)
    };

    let mut arkose_platform_har_path = Text::new("Platform ArkoseLabs HAR file ›")
        .with_render_config(render_config())
        .with_help_message("About the browser HAR file path requested by Platform ArkoseLabs")
        .with_validator(valid_file_path);
    if let Some(content) = conf.arkose_platform_har_path.as_deref() {
        arkose_platform_har_path = arkose_platform_har_path.with_initial_value(content)
    };

    let default_solver = Solver::default().to_string();
    let init_solver = conf.arkose_solver.to_string();
    let arkose_solver = Text::new("Arkose solver ›")
        .with_render_config(render_config())
        .with_help_message("About ArkoseLabs solver platform")
        .with_validator(valid_solver)
        .with_default(default_solver.as_str())
        .with_initial_value(init_solver.as_str());

    let mut arkose_solver_key = Text::new("Arkose solver key ›")
        .with_render_config(render_config())
        .with_help_message("About the solver client key by ArkoseLabs");
    if let Some(content) = conf.arkose_solver_key.as_deref() {
        arkose_solver_key = arkose_solver_key.with_initial_value(content)
    };

    conf.proxy = proxy
        .prompt_skippable()?
        .map(|ok| if ok.is_empty() { None } else { Some(ok) })
        .unwrap_or(conf.proxy);

    conf.official_api = official_api
        .prompt_skippable()?
        .map(|ok| if ok.is_empty() { None } else { Some(ok) })
        .unwrap_or(conf.official_api);

    conf.unofficial_api = unofficial_api
        .prompt_skippable()?
        .map(|ok| if ok.is_empty() { None } else { Some(ok) })
        .unwrap_or(conf.unofficial_api);

    conf.arkose_chat_har_path = arkose_chat_har_file
        .prompt_skippable()?
        .map(|ok| if ok.is_empty() { None } else { Some(ok) })
        .unwrap_or(conf.arkose_chat_har_path);

    conf.arkose_auth_har_path = arkose_auth_har_path
        .prompt_skippable()?
        .map(|ok| if ok.is_empty() { None } else { Some(ok) })
        .unwrap_or(conf.arkose_auth_har_path);

    conf.arkose_platform_har_path = arkose_platform_har_path
        .prompt_skippable()?
        .map(|ok| if ok.is_empty() { None } else { Some(ok) })
        .unwrap_or(conf.arkose_platform_har_path);

    conf.arkose_solver = arkose_solver.prompt()?.parse()?;

    conf.arkose_solver_key = arkose_solver_key
        .prompt_skippable()?
        .map(|ok| if ok.is_empty() { None } else { Some(ok) })
        .unwrap_or(conf.arkose_solver_key);

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

    let ans = Confirm::new("Are you sure you want to save the configuration?")
        .with_default(false)
        .prompt()?;

    if ans {
        store.store(conf)?;
    }

    Ok(())
}
