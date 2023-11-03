use crate::{arkose, homedir::home_dir, info, warn};
use hotwatch::{Event, Hotwatch};
use rand::seq::SliceRandom;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{OnceLock, RwLock},
};

pub(super) static HAR: OnceLock<RwLock<HashMap<arkose::Type, HarProvider>>> = OnceLock::new();

pub struct HarPath {
    pub dir_path: PathBuf,
    pub file_path: Option<PathBuf>,
}

#[derive(Debug)]
pub(super) struct HarProvider {
    /// HAR dir path
    dir_path: PathBuf,
    /// File Hotwatch
    hotwatch: Hotwatch,
    /// HAR file pool
    pool: Vec<String>,
}

impl HarProvider {
    pub(super) fn new(
        _type: arkose::Type,
        dir_path: Option<&PathBuf>,
        default_dir_name: &str,
    ) -> HarProvider {
        let dir_path = dir_path.cloned().unwrap_or(
            home_dir()
                .expect("Failed to get home directory")
                .join(default_dir_name),
        );

        init_directory(&dir_path);

        HarProvider {
            hotwatch: watch_har_dir(_type, &dir_path),
            dir_path,
            pool: Vec::new(),
        }
    }

    fn reset_pool(&mut self) {
        self.pool.clear();
        std::fs::read_dir(&self.dir_path)
            .expect("Failed to read har directory")
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|file_path| {
                file_path
                    .extension()
                    .map(|ext| ext == "har")
                    .unwrap_or(false)
            })
            .for_each(|file_path| {
                if let Some(file_name) = file_path.file_stem() {
                    self.pool.push(file_name.to_string_lossy().to_string());
                }
            });
    }

    pub(super) fn pool(&self) -> HarPath {
        let mut har_path = HarPath {
            dir_path: self.dir_path.clone(),
            file_path: None,
        };
        self.pool.choose(&mut rand::thread_rng()).map(|file_name| {
            har_path.file_path = Some(self.dir_path.join(format!("{file_name}.har")))
        });
        har_path
    }
}

fn init_directory(path: impl AsRef<Path>) {
    let path = path.as_ref();

    if !path.exists() {
        info!("Create default HAR empty file: {}", path.display());
        std::fs::create_dir_all(&path).expect("Failed to create har directory");
    }
}

fn watch_har_dir(_type: arkose::Type, path: impl AsRef<Path>) -> Hotwatch {
    let mut hotwatch = Hotwatch::new().expect("hotwatch failed to initialize!");
    hotwatch
        .watch(path.as_ref().display().to_string(), {
            let _type = _type;
            let watch_path = path.as_ref().display().to_string();
            info!("Start watching HAR directory: {}", watch_path);
            move |event: Event| match event.kind {
                _ => {
                    event.paths.iter().for_each(|path| {
                        info!(
                            "HAR directory: {watch_path} changes observed: {}",
                            path.display()
                        );
                        let lock = HAR.get().unwrap();
                        let mut har_map = lock.write().expect("Failed to get har map");
                        if let Some(har) = har_map.get_mut(&_type) {
                            // clear cache
                            if let Some(path_str) = path.as_path().to_str() {
                                arkose::har::clear_cache(path_str);
                                har.reset_pool();
                            }
                        }
                    });
                }
            }
        })
        .expect("failed to watch file!");
    hotwatch
}

impl Drop for HarProvider {
    fn drop(&mut self) {
        if let Some(err) = self.hotwatch.unwatch(self.dir_path.as_path()).err() {
            warn!("hotwatch stop error: {err}")
        }
    }
}
