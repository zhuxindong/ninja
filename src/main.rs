#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_env = "musl"
))]
use tikv_jemallocator::Jemalloc;

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_env = "musl"
))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use args::SubCommands;
use clap::Parser;

pub mod args;
pub mod args_handle;
pub mod conf;
pub mod env;
pub mod inter;
pub mod util;

fn main() -> anyhow::Result<()> {
    let opt = args::Opt::parse();
    std::env::set_var("RUST_LOG", opt.level);
    match opt.command {
        Some(command) => match command {
            SubCommands::Config {
                workdir: _,
                unofficial_api: _,
                unofficial_proxy: _,
            } => {}
            SubCommands::Serve(commands) => match commands {
                args::ServeSubcommand::Run(args) => args_handle::serve(args, true)?,
                #[cfg(target_family = "unix")]
                args::ServeSubcommand::Stop => args_handle::serve_stop()?,
                #[cfg(target_family = "unix")]
                args::ServeSubcommand::Start(args) => args_handle::serve_start(args)?,
                #[cfg(target_family = "unix")]
                args::ServeSubcommand::Restart(args) => args_handle::serve_restart(args)?,
                #[cfg(target_family = "unix")]
                args::ServeSubcommand::Status => args_handle::serve_status()?,
                #[cfg(target_family = "unix")]
                args::ServeSubcommand::Log => args_handle::serve_log()?,
                args::ServeSubcommand::GT { out, edit } => {
                    args_handle::generate_template(out)?;
                    args_handle::edit_template_file(edit)?;
                }
            },
        },
        None => {}
    }
    Ok(())
}
