#![doc = include_str!("../README.md")]
#![cfg_attr(not(any(test, feature = "stores")), no_std)]
#![cfg_attr(not(test), deny(clippy::indexing_slicing))]

mod ladder;
mod source;

#[cfg(feature = "stores")]
pub mod stores;

pub use ladder::{ConfigError, Custody, Ladder, Mint, Open, Refusal};
pub use source::{
    Access, Durability, Fingerprint, Observation, SourceId, SourceSet, SourceSpec, Vault,
};
