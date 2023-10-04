pub mod account;
pub mod conf;

use serde::de::DeserializeOwned;

pub type StoreResult<T, E = anyhow::Error> = anyhow::Result<T, E>;

pub trait StoreId {
    fn id(&self) -> String;
}

pub trait Store<T: DeserializeOwned + serde::Serialize + StoreId>: Send + Sync + 'static {
    type Obj;
    // Add store target return an old target
    fn store(&self, target: T) -> StoreResult<Option<Self::Obj>>;

    // Read target return a copy of the target
    fn read(&self, target: T) -> StoreResult<Option<Self::Obj>>;

    // Delete target return an current target
    fn remove(&self, target: T) -> StoreResult<Option<Self::Obj>>;

    /// List target return an current target list
    fn list(&self) -> StoreResult<Vec<Self::Obj>>;
}
