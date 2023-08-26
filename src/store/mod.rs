use serde::de::DeserializeOwned;

pub mod account;
pub mod conf;

pub type StoreResult<T, E = anyhow::Error> = anyhow::Result<T, E>;

pub trait StoreId {
    fn id(&self) -> String;
}

pub trait Store<T: DeserializeOwned + serde::Serialize + StoreId>: Send + Sync + 'static {
    // Add store target return an old target
    fn add(&self, target: T) -> StoreResult<Option<T>>;

    // Read target return a copy of the target
    fn get(&self, target: T) -> StoreResult<Option<T>>;

    // Delete target return an current target
    fn remove(&self, target: T) -> StoreResult<Option<T>>;

    /// List target return an current target list
    fn list(&self) -> StoreResult<Vec<T>>;
}
