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
pub mod env;
pub mod handle;
pub mod homedir;
pub mod inter;
pub mod store;
pub mod util;

fn main() -> anyhow::Result<()> {
    let opt = args::Opt::parse();
    std::env::set_var("RUST_LOG", opt.level);
    match opt.command {
        Some(command) => match command {
            SubCommands::Serve(commands) => match commands {
                args::ServeSubcommand::Run(args) => handle::serve(args, true)?,
                #[cfg(target_family = "unix")]
                args::ServeSubcommand::Stop => handle::serve_stop()?,
                #[cfg(target_family = "unix")]
                args::ServeSubcommand::Start(args) => handle::serve_start(args)?,
                #[cfg(target_family = "unix")]
                args::ServeSubcommand::Restart(args) => handle::serve_restart(args)?,
                #[cfg(target_family = "unix")]
                args::ServeSubcommand::Status => handle::serve_status()?,
                #[cfg(target_family = "unix")]
                args::ServeSubcommand::Log => handle::serve_log()?,
                args::ServeSubcommand::GT { out, edit } => {
                    handle::generate_template(out)?;
                    handle::edit_template_file(edit)?;
                }
            },
            SubCommands::Terminal => inter::prompt()?,
        },
        None => {}
    }
    Ok(())
}
