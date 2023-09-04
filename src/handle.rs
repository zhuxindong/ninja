use std::{env, ffi::OsString, ops::Not, path::PathBuf};

use anyhow::bail;
use inquire::ui::{Color, RenderConfig, Styled};

use crate::{
    args::{self, ServeArgs},
    env::fix_relative_path,
};

pub(super) fn serve(mut args: ServeArgs, relative_path: bool) -> anyhow::Result<()> {
    if relative_path {
        fix_relative_path(&mut args);
    }

    if let Some(config_path) = args.config {
        let bytes = std::fs::read(config_path)?;
        let data = String::from_utf8(bytes)?;
        args = toml::from_str::<ServeArgs>(&data)?;
    }

    let puid_user = if let Some(puid_user) = args.puid_user {
        (Some(puid_user.0), Some(puid_user.1), puid_user.2)
    } else {
        (None, None, None)
    };

    let mut builder = openai::serve::LauncherBuilder::default();
    let builder = builder
        .host(
            args.host
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
        )
        .port(args.port.unwrap_or(7999))
        .proxies(args.proxies.unwrap_or_default())
        .api_prefix(args.api_prefix)
        .arkose_endpoint(args.arkose_endpoint)
        .arkose_har_path(args.arkose_har_path)
        .arkose_har_upload_key(args.arkose_har_upload_key)
        .arkose_token_endpoint(args.arkose_token_endpoint)
        .tls_keypair(None)
        .tcp_keepalive(args.tcp_keepalive)
        .timeout(args.timeout)
        .connect_timeout(args.connect_timeout)
        .workers(args.workers)
        .concurrent_limit(args.concurrent_limit)
        .cf_site_key(args.cf_site_key)
        .cf_secret_key(args.cf_secret_key)
        .disable_ui(args.disable_webui)
        .puid(args.puid)
        .puid_email(puid_user.0)
        .puid_password(puid_user.1)
        .yescaptcha_client_key(args.arkose_yescaptcha_key)
        .puid_mfa(puid_user.2);

    #[cfg(feature = "limit")]
    let builder = builder
        .tb_enable(args.tb_enable)
        .tb_store_strategy(args.tb_store_strategy)
        .tb_redis_url(args.tb_redis_url)
        .tb_capacity(args.tb_capacity)
        .tb_fill_rate(args.tb_fill_rate)
        .tb_expired(args.tb_expired);

    #[cfg(feature = "sign")]
    let mut builder = builder.sign_secret_key(args.sign_secret_key);

    if args.tls_key.is_some() && args.tls_cert.is_some() {
        builder = builder.tls_keypair(Some((args.tls_cert.unwrap(), args.tls_key.unwrap())));
    }
    builder.build()?.run()
}

#[cfg(target_family = "unix")]
pub(super) fn serve_start(mut args: ServeArgs) -> anyhow::Result<()> {
    use crate::env::{self, check_root, get_pid};
    use daemonize::Daemonize;
    use std::{
        fs::{File, Permissions},
        os::unix::prelude::PermissionsExt,
    };

    check_root();

    if let Some(pid) = get_pid() {
        println!("OpenGPT is already running with pid: {}", pid);
        return Ok(());
    }

    let pid_file = File::create(env::PID_PATH).unwrap();
    pid_file.set_permissions(Permissions::from_mode(0o755))?;

    let stdout = File::create(env::DEFAULT_STDOUT_PATH).unwrap();
    stdout.set_permissions(Permissions::from_mode(0o755))?;

    let stderr = File::create(env::DEFAULT_STDERR_PATH).unwrap();
    stdout.set_permissions(Permissions::from_mode(0o755))?;

    let mut daemonize = Daemonize::new()
        .pid_file(env::PID_PATH) // Every method except `new` and `start`
        .chown_pid_file(true) // is optional, see `Daemonize` documentation
        .working_directory(env::DEFAULT_WORK_DIR) // for default behaviour.
        .umask(0o777) // Set umask, `0o027` by default.
        .stdout(stdout) // Redirect stdout to `/tmp/daemon.out`.
        .stderr(stderr) // Redirect stderr to `/tmp/daemon.err`.
        .privileged_action(|| "Executed before drop privileges");

    match std::env::var("SUDO_USER") {
        Ok(user) => {
            if let Ok(Some(real_user)) = nix::unistd::User::from_name(&user) {
                daemonize = daemonize
                    .user(real_user.name.as_str())
                    .group(real_user.gid.as_raw());
            }
        }
        Err(_) => println!("Could not interpret SUDO_USER"),
    }

    fix_relative_path(&mut args);

    match daemonize.start() {
        Ok(_) => println!("Success, daemonized"),
        Err(e) => println!("Error, {}", e),
    }

    serve(args, false)
}

#[cfg(target_family = "unix")]
pub(super) fn serve_stop() -> anyhow::Result<()> {
    use crate::env::{self, check_root, get_pid};
    use nix::sys::signal;
    use nix::unistd::Pid;

    check_root();

    if let Some(pid) = get_pid() {
        let pid = pid.parse::<i32>()?;
        for _ in 0..360 {
            if let Err(_) = nix::sys::signal::kill(Pid::from_raw(pid), signal::SIGINT) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1))
        }
        let _ = std::fs::remove_file(env::PID_PATH);
    }

    Ok(())
}

#[cfg(target_family = "unix")]
pub(super) fn serve_restart(args: ServeArgs) -> anyhow::Result<()> {
    use crate::env::check_root;

    check_root();
    println!("Restarting OpenGPT...");
    serve_stop()?;
    serve_start(args)
}

#[cfg(target_family = "unix")]
pub(super) fn serve_status() -> anyhow::Result<()> {
    use crate::env::get_pid;
    match get_pid() {
        Some(pid) => println!("OpenGPT is running with pid: {}", pid),
        None => println!("OpenGPT is not running"),
    }
    Ok(())
}

#[cfg(target_family = "unix")]
pub(super) fn serve_log() -> anyhow::Result<()> {
    use crate::env;
    use std::{
        fs::File,
        io::{self, BufRead},
        path::Path,
    };

    let path = Path::new(env::DEFAULT_STDOUT_PATH);
    let file = File::open(&path)?;
    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        match line {
            Ok(content) => println!("{}", content),
            Err(err) => eprintln!("Error reading line: {}", err),
        }
    }
    Ok(())
}

pub(super) fn edit_template_file(edit: Option<PathBuf>) -> anyhow::Result<()> {
    if let Some(path) = edit {
        if !path.is_file() {
            bail!("{} not is file", path.display())
        }

        let extention = if let Some(extention) = path.extension() {
            format!(".{:?}", extention)
        } else {
            "".to_owned()
        };

        fn get_default_editor() -> OsString {
            if let Some(prog) = env::var_os("VISUAL") {
                return prog;
            }
            if let Some(prog) = env::var_os("EDITOR") {
                return prog;
            }
            if cfg!(windows) {
                "notepad.exe".into()
            } else {
                "vi".into()
            }
        }

        let file_string = std::fs::read_to_string(&path)?;

        let mut edit_content = inquire::Editor::new("Edit:")
            .with_editor_command(&get_default_editor())
            .with_render_config(RenderConfig::default().with_canceled_prompt_indicator(
                Styled::new("<skipped>").with_fg(Color::DarkYellow),
            ))
            .with_file_extension(&extention)
            .with_predefined_text(&file_string)
            .prompt()?;

        println!("------------Edit Complete------------\n{}", edit_content);

        edit_content.push('\n');

        std::fs::write(path, edit_content)?
    }
    Ok(())
}

pub(super) fn generate_template(out: Option<PathBuf>) -> anyhow::Result<()> {
    let out = if let Some(out) = out {
        match out.is_dir() {
            false => {
                if let Some(parent) = out.parent() {
                    if parent.exists().not() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
            }
            true => anyhow::bail!("{} not a file", out.display()),
        };
        out
    } else {
        std::env::current_dir()?.join("serve.toml")
    };

    let args = args::ServeArgs {
        config: None,
        host: Some("0.0.0.0".parse().unwrap()),
        port: Some(7999),
        workers: 1,
        concurrent_limit: 65535,
        proxies: None,
        timeout: 600,
        connect_timeout: 60,
        tcp_keepalive: 60,
        tls_cert: None,
        tls_key: None,
        api_prefix: None,
        arkose_endpoint: None,
        arkose_token_endpoint: None,
        sign_secret_key: None,
        tb_enable: false,
        tb_store_strategy: openai::serve::tokenbucket::Strategy::Mem,
        tb_redis_url: "redis://127.0.0.1:6379".to_string(),
        tb_capacity: 60,
        tb_fill_rate: 1,
        tb_expired: 86400,
        cf_site_key: None,
        cf_secret_key: None,
        disable_webui: false,
        puid_user: None,
        puid: None,
        arkose_yescaptcha_key: None,
        arkose_har_path: None,
        arkose_har_upload_key: None,
    };

    let write = |out: PathBuf, args: ServeArgs| -> anyhow::Result<()> {
        #[cfg(target_family = "unix")]
        {
            use std::fs::Permissions;
            use std::os::unix::prelude::PermissionsExt;
            std::fs::File::create(&out)?.set_permissions(Permissions::from_mode(0o755))?;
        }

        #[cfg(target_family = "windows")]
        std::fs::File::create(&out)?;

        Ok(std::fs::write(out, toml::to_string_pretty(&args)?)?)
    };

    if !out.exists() {
        write(out, args)?;
    }
    Ok(())
}
