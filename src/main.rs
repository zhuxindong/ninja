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

use clap::Parser;

#[cfg(feature = "terminal")]
pub mod inter;
#[cfg(feature = "terminal")]
pub mod store;

mod args;
mod handle;
mod parse;
mod update;
mod utils;

fn main() -> anyhow::Result<()> {
    let opt = args::cmd::Opt::parse();

    #[cfg(all(feature = "serve", not(feature = "terminal")))]
    if let Some(command) = opt.command {
        match command {
            args::ServeSubcommand::Run(args) => handle::serve(args, false)?,
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
            args::ServeSubcommand::Genca => {
                let _ = openai::serve::preauth::cagen::gen_ca();
            }
            args::ServeSubcommand::GT { out } => handle::generate_template(out)?,
            args::ServeSubcommand::Update => update::update()?,
        }
    }

    #[cfg(all(feature = "serve", feature = "terminal"))]
    if let Some(command) = opt.command {
        use args::cmd::SubCommands;
        match command {
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
                args::ServeSubcommand::Genca => {
                    let _ = openai::serve::preauth::cagen::gen_ca();
                }
                args::ServeSubcommand::GT { out } => handle::generate_template(out)?,
                args::ServeSubcommand::Update => update::update()?,
            },
            SubCommands::Terminal => {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .worker_threads(1)
                    .max_blocking_threads(1)
                    .build()?;

                runtime.block_on(inter::prompt())?;
            }
        }
    }

    Ok(())
}
