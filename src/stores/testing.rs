//! An in-memory source for tests: put a key, wipe it as a reboot would, or
//! make it unreachable or refuse writes.

use std::sync::{Arc, Mutex, PoisonError};

use zeroize::Zeroizing;

use super::{Secret, Sighting, Source, SourceError};
use crate::SourceSpec;

/// A source in memory. Clones share the same slot. `Debug` never shows the key.
#[derive(Clone)]
pub struct MemorySource {
    name: String,
    spec: SourceSpec,
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    key: Option<Zeroizing<Vec<u8>>>,
    unreachable: bool,
    refuse_writes: bool,
    lose_writes: bool,
    writes: usize,
}

impl MemorySource {
    /// A durable, writable source.
    #[must_use]
    pub fn durable(name: impl Into<String>) -> Self {
        Self::new(name, SourceSpec::durable())
    }

    /// A durable source provisioned by someone else.
    #[must_use]
    pub fn provisioned(name: impl Into<String>) -> Self {
        Self::new(name, SourceSpec::provisioned())
    }

    /// A cache that a reboot wipes.
    #[must_use]
    pub fn cache(name: impl Into<String>) -> Self {
        Self::new(name, SourceSpec::cache())
    }

    /// A source with `spec`.
    #[must_use]
    pub fn new(name: impl Into<String>, spec: SourceSpec) -> Self {
        Self {
            name: name.into(),
            spec,
            state: Arc::default(),
        }
    }

    /// Put `key` in the source, as if someone else stored it.
    pub fn put(&self, key: &[u8]) {
        self.with(|state| state.key = Some(Zeroizing::new(key.to_vec())));
    }

    /// Drop the key, as a reboot drops a cache.
    pub fn wipe(&self) {
        self.with(|state| state.key = None);
    }

    /// Make reads answer [`Sighting::Unreachable`].
    pub fn set_unreachable(&self, unreachable: bool) {
        self.with(|state| state.unreachable = unreachable);
    }

    /// Make writes fail.
    pub fn refuse_writes(&self, refuse: bool) {
        self.with(|state| state.refuse_writes = refuse);
    }

    /// Make writes answer `Ok` and store nothing.
    pub fn lose_writes(&self, lose: bool) {
        self.with(|state| state.lose_writes = lose);
    }

    /// The key the source holds.
    #[must_use]
    pub fn held(&self) -> Option<Secret> {
        self.with(|state| state.key.clone())
    }

    /// Whether the source holds exactly `key`.
    #[must_use]
    pub fn holds(&self, key: &[u8]) -> bool {
        self.with(|state| {
            state
                .key
                .as_deref()
                .is_some_and(|held| held.as_slice() == key)
        })
    }

    /// How many writes succeeded.
    #[must_use]
    pub fn writes(&self) -> usize {
        self.with(|state| state.writes)
    }

    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        f(&mut self.state.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl std::fmt::Debug for MemorySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemorySource")
            .field("name", &self.name)
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

impl Source for MemorySource {
    fn name(&self) -> &str {
        &self.name
    }

    fn spec(&self) -> SourceSpec {
        self.spec
    }

    fn read(&self) -> Sighting {
        self.with(|state| {
            if state.unreachable {
                return Sighting::Unreachable(SourceError::new("unreachable for the test"));
            }
            state.key.clone().map_or(Sighting::Empty, Sighting::Holds)
        })
    }

    fn write(&self, key: &[u8]) -> Result<(), SourceError> {
        self.with(|state| {
            if state.unreachable || state.refuse_writes {
                return Err(SourceError::new("writes refused for the test"));
            }
            if !state.lose_writes {
                state.key = Some(Zeroizing::new(key.to_vec()));
            }
            state.writes += 1;
            Ok(())
        })
    }
}
