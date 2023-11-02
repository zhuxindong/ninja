use crate::{arkose, homedir::home_dir, info, warn};
use hotwatch::{Event, EventKind, Hotwatch};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{OnceLock, RwLock},
};

pub(super) static HAR: OnceLock<RwLock<HashMap<arkose::Type, HarProvider>>> = OnceLock::new();

#[derive(Debug)]
pub(super) struct HarProvider {
    /// HAR file path
    pub(super) path: PathBuf,
    /// HAR file state (file changed)
    pub(super) state: bool,
    /// File Hotwatch
    pub(super) hotwatch: Hotwatch,
}

impl HarProvider {
    pub(super) fn init_har(
        _type: arkose::Type,
        path: &Option<PathBuf>,
        default_filename: &str,
    ) -> HarProvider {
        if let Some(file_path) = path {
            return HarProvider {
                path: file_path.to_owned(),
                state: true,
                hotwatch: Self::watch_har_file(_type, &file_path),
            };
        }

        let default_path = home_dir()
            .expect("Failed to get home directory")
            .join(default_filename);

        let state = match default_path.is_file() {
            true => {
                let har_data = std::fs::read(&default_path).expect("Failed to read har file");
                !har_data.is_empty()
            }
            false => {
                info!("Create default HAR empty file: {}", default_path.display());
                let har_file =
                    std::fs::File::create(&default_path).expect("Failed to create har file");
                drop(har_file);
                false
            }
        };

        HarProvider {
            hotwatch: Self::watch_har_file(_type, &default_path),
            path: default_path,
            state,
        }
    }

    fn watch_har_file(_type: arkose::Type, path: &PathBuf) -> Hotwatch {
        let watch_path = path.display();
        let mut hotwatch = Hotwatch::new().expect("hotwatch failed to initialize!");
        hotwatch
            .watch(watch_path.to_string(), {
                let _type = _type;
                move |event: Event| {
                    if let EventKind::Modify(_) = event.kind {
                        event.paths.iter().for_each(|path| {
                            info!("HAR file changes observed: {}", path.display());
                            let lock = HAR.get().expect("Failed to get har lock");
                            let mut har_map = lock.write().expect("Failed to get har map");
                            if let Some(har) = har_map.get_mut(&_type) {
                                har.state = true;
                                match path.to_str() {
                                    Some(path_str) => arkose::har::clear(path_str),
                                    None => warn!("Failed to convert path to string"),
                                }
                            }
                        });
                    }
                }
            })
            .expect("failed to watch file!");
        hotwatch
    }
}

impl Drop for HarProvider {
    fn drop(&mut self) {
        if let Some(err) = self.hotwatch.unwatch(self.path.as_path()).err() {
            warn!("hotwatch stop error: {err}")
        }
    }
}
