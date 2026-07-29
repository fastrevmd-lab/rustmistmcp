//! Mist-specific models and client adapters.
//!
//! The crate boundary is established here; Task 2 adds the first public types.

pub mod catalog;

mod config;
mod grant;
mod target;

pub use catalog::MistAction;
pub use config::{ConfigError, MistConfig};
pub use grant::MistGrant;
pub use target::{MistTarget, MistTargetError};
