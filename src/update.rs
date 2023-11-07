use std::env;

use self_update::cargo_crate_version;

pub(super) fn update() -> anyhow::Result<()> {
    use self_update::update::UpdateStatus;
    let status = self_update::backends::github::Update::configure()
        .repo_owner("gngpp")
        .repo_name("ninja")
        .bin_name("ninja")
        .target(self_update::get_target())
        .show_output(true)
        .show_download_progress(true)
        .no_confirm(true)
        .current_version(cargo_crate_version!())
        .build()?
        .update_extended()?;
    if let UpdateStatus::Updated(ref release) = status {
        if let Some(body) = &release.body {
            if !body.trim().is_empty() {
                println!("ninja upgraded to {}:\n", release.version);
                println!("{}", body);
            } else {
                println!("ninja upgraded to {}", release.version);
            }
        }
    } else {
        println!("ninja is up-to-date");
    }

    Ok(())
}
