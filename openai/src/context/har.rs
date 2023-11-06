use crate::{arkose, homedir::home_dir, info, warn};
use hotwatch::{Event, EventKind, Hotwatch};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        OnceLock, RwLock,
    },
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
    index: AtomicUsize,
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

        let mut pool = Vec::new();
        Self::init_pool(&dir_path, &mut pool);

        HarProvider {
            pool,
            hotwatch: watch_har_dir(_type, &dir_path),
            dir_path,
            index: AtomicUsize::new(0),
        }
    }

    fn init_pool(dir_path: impl AsRef<Path>, pool: &mut Vec<String>) {
        std::fs::read_dir(dir_path.as_ref())
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
                    pool.push(format!("{}.har", file_name.to_string_lossy()));
                }
            });
    }

    fn reset_pool(&mut self) {
        self.pool.clear();
        Self::init_pool(&self.dir_path, &mut self.pool)
    }

    pub(super) fn pool(&self) -> HarPath {
        let mut har_path = HarPath {
            dir_path: self.dir_path.clone(),
            file_path: None,
        };

        if self.pool.is_empty() {
            return har_path;
        }

        let len = self.pool.len();
        let mut old = self.index.load(Ordering::Relaxed);
        let mut new;
        loop {
            new = (old + 1) % len;
            match self
                .index
                .compare_exchange_weak(old, new, Ordering::SeqCst, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(x) => old = x,
            }
        }

        har_path.file_path = Some(self.dir_path.join(&self.pool[new]));
        har_path
    }
}

fn init_directory(path: impl AsRef<Path>) {
    let path = path.as_ref();

    if !path.exists() {
        info!("Create default HAR directory: {}", path.display());
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
                EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
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
                _ => {}
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
