use std::{ops::Not, path::PathBuf};

use clap::CommandFactory;
use openai::{arkose::funcaptcha::Solver, serve::tokenbucket::Strategy};

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

    // disable_direct and proxies are mutually exclusive
    if args.disable_direct {
        if args.proxies.is_none() || args.proxies.clone().is_some_and(|x| x.is_empty()) {
            let mut cmd = args::Opt::command();
            cmd.error(
                clap::error::ErrorKind::ArgumentConflict,
                "Cannot disable direct connection and not set proxies",
            )
            .exit();
        }
    }

    let mut builder = openai::serve::LauncherBuilder::default();
    let builder = builder
        .host(
            args.host
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
        )
        .port(args.port.unwrap_or(7999))
        .proxies(args.proxies.unwrap_or_default())
        .disable_direct(args.disable_direct)
        .api_prefix(args.api_prefix)
        .arkose_endpoint(args.arkose_endpoint)
        .arkose_chat_har_path(args.arkose_chat_har_path)
        .arkose_auth_har_path(args.arkose_auth_har_path)
        .arkose_platform_har_path(args.arkose_platform_har_path)
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
        .arkose_solver(args.arkose_solver)
        .arkose_solver_key(args.arkose_solver_key)
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
        builder = builder.tls_keypair(Some((
            args.tls_cert.expect("tls_cert not init"),
            args.tls_key.expect("tls_key not init"),
        )));
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
        println!("Ninja is already running with pid: {}", pid);
        return Ok(());
    }

    let pid_file = File::create(env::PID_PATH)?;
    pid_file.set_permissions(Permissions::from_mode(0o755))?;

    let stdout = File::create(env::DEFAULT_STDOUT_PATH)?;
    stdout.set_permissions(Permissions::from_mode(0o755))?;

    let stderr = File::create(env::DEFAULT_STDERR_PATH)?;
    stdout.set_permissions(Permissions::from_mode(0o755))?;

    let mut daemonize = Daemonize::new()
        .pid_file(env::PID_PATH) // Every method except `new` and `start`
        .chown_pid_file(true) // is optional, see `Daemonize` documentation
        .working_directory(env::DEFAULT_WORK_DIR) // for default behaviour.
        .umask(0o777) // Set umask, `0o027` by default.
        .stdout(stdout) // Redirect stdout to `/tmp/daemon.out`.
        .stderr(stderr) // Redirect stderr to `/tmp/daemon.err`.
        .privileged_action(|| "Executed before drop privileges");

    if let Ok(user) = std::env::var("SUDO_USER") {
        if let Ok(Some(real_user)) = nix::unistd::User::from_name(&user) {
            daemonize = daemonize
                .user(real_user.name.as_str())
                .group(real_user.gid.as_raw());
        }
    }

    fix_relative_path(&mut args);

    if let Some(err) = daemonize.start().err() {
        eprintln!("Error: {err}")
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
            if nix::sys::signal::kill(Pid::from_raw(pid), signal::SIGINT).is_err() {
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
    serve_stop()?;
    serve_start(args)
}

#[cfg(target_family = "unix")]
pub(super) fn serve_status() -> anyhow::Result<()> {
    use crate::env::get_pid;
    match get_pid() {
        Some(pid) => println!("Ninja is running with pid: {}", pid),
        None => println!("Ninja is not running"),
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

    fn read_and_print_file(file_path: &Path, placeholder: &str) -> anyhow::Result<()> {
        // Check if the file is empty before opening it
        let metadata = std::fs::metadata(file_path)?;
        if metadata.len() == 0 {
            return Ok(());
        }

        let file = File::open(file_path)?;
        let reader = io::BufReader::new(file);
        let mut start = true;

        for line in reader.lines() {
            if let Ok(content) = line {
                if start {
                    start = false;
                    println!("{placeholder}");
                }
                println!("{}", content);
            } else if let Err(err) = line {
                eprintln!("Error reading line: {}", err);
            }
        }

        Ok(())
    }

    let stdout_path = Path::new(env::DEFAULT_STDOUT_PATH);
    read_and_print_file(stdout_path, "STDOUT>")?;

    let stderr_path = Path::new(env::DEFAULT_STDERR_PATH);
    read_and_print_file(stderr_path, "STDERR>")?;

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
        host: Some("0.0.0.0".parse()?),
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
        tb_store_strategy: Strategy::Mem,
        tb_redis_url: "redis://127.0.0.1:6379".to_string(),
        tb_capacity: 60,
        tb_fill_rate: 1,
        tb_expired: 86400,
        cf_site_key: None,
        cf_secret_key: None,
        disable_webui: false,
        puid_user: None,
        puid: None,
        arkose_chat_har_path: None,
        arkose_har_upload_key: None,
        disable_direct: false,
        arkose_solver: Solver::Yescaptcha,
        arkose_solver_key: None,
        arkose_platform_har_path: None,
        arkose_auth_har_path: None,
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
