use crate::args::ServeArgs;

#[cfg(target_family = "unix")]
pub(crate) const PID_PATH: &str = "/var/run/ninja.pid";
#[cfg(target_family = "unix")]
pub(crate) const DEFAULT_STDOUT_PATH: &str = "/var/run/ninja.out";
#[cfg(target_family = "unix")]
pub(crate) const DEFAULT_STDERR_PATH: &str = "/var/run/ninja.err";
#[cfg(target_family = "unix")]
pub(crate) const DEFAULT_WORK_DIR: &str = "/";

#[cfg(target_family = "unix")]
pub(crate) fn check_root() {
    use nix::unistd::Uid;

    if !Uid::effective().is_root() {
        println!("You must run this executable with root permissions");
        std::process::exit(-1)
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn sysctl_ipv6_no_local_bind(enable: bool) {
    if !enable {
        return;
    }

    use nix::unistd::Uid;

    if !Uid::effective().is_root() {
        return;
    }

    use sysctl::Sysctl;
    const CTLNAME: &str = "net.ipv6.ip_nonlocal_bind";

    let ctl = <sysctl::Ctl as Sysctl>::new(CTLNAME)
        .expect(&format!("could not get sysctl '{}'", CTLNAME));
    let _ = ctl.name().expect("could not get sysctl name");

    let old_value = ctl.value_string().expect("could not get sysctl value");

    let target_value = match old_value.as_ref() {
        "0" => "1",
        "1" | _ => &old_value,
    };

    ctl.set_value_string(target_value).unwrap_or_else(|e| {
        panic!(
            "could not set sysctl '{}' to '{}': {}",
            CTLNAME, target_value, e
        )
    });
}

#[cfg(target_family = "unix")]
pub(crate) fn get_pid() -> Option<String> {
    if let Ok(data) = std::fs::read(PID_PATH) {
        let binding = String::from_utf8(data).expect("pid file is not utf8");
        return Some(binding.trim().to_string());
    }
    None
}

pub(crate) fn fix_relative_path(args: &mut ServeArgs) {
    if let Some(c) = args.config.as_mut() {
        // fix relative path
        if c.is_relative() {
            args.config = Some(
                std::env::current_dir()
                    .expect("cannot get current exe")
                    .join(c),
            )
        }
    }
}
