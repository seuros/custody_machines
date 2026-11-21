use core::fmt;

use crate::source::{Fingerprint, Observation, SourceId, SourceSet, SourceSpec, Vault};

/// Key sources in preference order, at least one of them durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ladder<const N: usize> {
    specs: [SourceSpec; N],
}

/// A ladder that cannot keep a key safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigError {
    /// Every source is volatile: the key would die with the next reboot.
    NoDurableSource,
}

/// Why the kernel will not honour a request. Nothing changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// Data is sealed, every source answered, and none holds a key.
    Lost,
    /// Data is sealed, no reachable source holds a key, and some source did
    /// not answer. Retry once it does; never mint over it.
    Unavailable,
    /// Two sources hold different keys over sealed data. Prove which one
    /// opens the vault and observe the other as [`Observation::Rejected`].
    /// Durable holders rank before volatile ones, then by position.
    Divergent {
        /// The highest-ranked holder.
        a: SourceId,
        /// The highest-ranked holder that disagrees with it.
        b: SourceId,
    },
    /// The only copy of the key dies with the next reboot: write nothing under it.
    VolatileOnly,
    /// No reachable durable source accepts writes, so a new key would be lost.
    NoDurableSink,
    /// Data is already sealed: open the key that sealed it instead of minting.
    Sealed,
    /// A source already holds a key: open it instead of minting.
    Occupied,
    /// Nothing is sealed and no source holds a key: mint one.
    Vacant,
}

/// Where the key's only safe copy lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Custody {
    /// A durable source holds the key.
    Durable,
    /// Only volatile sources hold the key.
    VolatileOnly,
}

/// An honoured open: where the key comes from, and where to copy it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Open {
    /// The source to take the key from.
    pub authority: SourceId,
    /// The key's fingerprint.
    pub fingerprint: Fingerprint,
    /// Sources to write the key into: stale or empty caches, and the most
    /// preferred empty durable source above the best durable holder.
    pub copy_to: SourceSet,
    /// Whether a durable source holds the key now, before any copy.
    pub custody: Custody,
}

impl Open {
    /// Whether data may be sealed under this key.
    ///
    /// # Errors
    ///
    /// [`Refusal::VolatileOnly`] when no durable source holds the key.
    pub const fn permit_write(&self) -> Result<(), Refusal> {
        match self.custody {
            Custody::Durable => Ok(()),
            Custody::VolatileOnly => Err(Refusal::VolatileOnly),
        }
    }
}

/// An honoured mint: where to store a fresh key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mint {
    /// The durable source to store the new key in first.
    pub target: SourceId,
    /// Caches to fill once the target holds it.
    pub cache: SourceSet,
}

#[derive(Clone, Copy)]
struct Seen {
    id: SourceId,
    spec: SourceSpec,
    observed: Observation,
}

impl<const N: usize> Ladder<N> {
    /// Build a ladder, most preferred source first. At most 16 sources.
    ///
    /// # Errors
    ///
    /// [`ConfigError::NoDurableSource`] when every source is volatile.
    pub fn new(specs: [SourceSpec; N]) -> Result<Self, ConfigError> {
        const { assert!(N > 0 && N <= 16, "a ladder holds 1 to 16 sources") };
        if specs.iter().any(|spec| spec.is_durable()) {
            Ok(Self { specs })
        } else {
            Err(ConfigError::NoDurableSource)
        }
    }

    /// The spec of the source at `id`.
    #[must_use]
    pub fn spec(&self, id: SourceId) -> Option<SourceSpec> {
        self.specs.get(id.index()).copied()
    }

    /// The sources, most preferred first.
    #[must_use]
    pub const fn specs(&self) -> &[SourceSpec; N] {
        &self.specs
    }

    /// Decide which key to use and where to copy it.
    ///
    /// A durable holder outranks every volatile one. Copies go to writable
    /// caches that are empty, stale or rejected, and to the most preferred
    /// writable durable source that answered empty and ranks above the best
    /// durable holder: that rescues a cache-only key and moves a key up when a
    /// better source appears. Read-only, unreachable and rejected durable
    /// sources are never written.
    ///
    /// # Errors
    ///
    /// [`Refusal::Vacant`], [`Refusal::Lost`], [`Refusal::Unavailable`] or
    /// [`Refusal::Divergent`].
    pub fn open(&self, observed: &[Observation; N], vault: Vault) -> Result<Open, Refusal> {
        let Some((first, first_fp)) = self.ranked(observed).next() else {
            return Err(Self::missing(observed, vault));
        };
        let fp = match vault {
            Vault::Sealed => {
                if let Some((other, _)) = self.ranked(observed).find(|(_, fp)| *fp != first_fp) {
                    return Err(Refusal::Divergent {
                        a: first.id,
                        b: other.id,
                    });
                }
                first_fp
            }
            Vault::Unsealed => self
                .holders(observed)
                .find(|(seen, _)| seen.spec.is_durable())
                .map_or(first_fp, |(_, fp)| fp),
        };
        let durable_holder = self
            .holders(observed)
            .find(|(seen, held)| *held == fp && seen.spec.is_durable())
            .map(|(seen, _)| seen);
        let authority = durable_holder
            .or_else(|| {
                self.holders(observed)
                    .find(|(_, held)| *held == fp)
                    .map(|(seen, _)| seen)
            })
            .map_or(first.id, |seen| seen.id);

        let mut copy_to = self
            .seen(observed)
            .filter(|seen| seen.spec.is_writable() && !seen.spec.is_durable())
            .filter(|seen| match seen.observed {
                Observation::Empty | Observation::Rejected(_) => true,
                Observation::Holds(other) => other != fp,
                Observation::Unreachable => false,
            })
            .fold(SourceSet::EMPTY, |set, seen| set.with(seen.id));
        let ceiling = durable_holder.map_or(N, |seen| seen.id.index());
        if let Some(target) = self.seen(observed).take(ceiling).find(|seen| {
            seen.spec.is_durable() && seen.spec.is_writable() && seen.observed == Observation::Empty
        }) {
            copy_to = copy_to.with(target.id);
        }

        let custody = if durable_holder.is_some() {
            Custody::Durable
        } else {
            Custody::VolatileOnly
        };
        Ok(Open {
            authority,
            fingerprint: fp,
            copy_to,
            custody,
        })
    }

    /// Decide where a fresh key goes. Only when nothing is sealed and no
    /// source holds a key.
    ///
    /// # Errors
    ///
    /// [`Refusal::Sealed`], [`Refusal::Occupied`] or [`Refusal::NoDurableSink`].
    pub fn mint(&self, observed: &[Observation; N], vault: Vault) -> Result<Mint, Refusal> {
        if vault == Vault::Sealed {
            return Err(Refusal::Sealed);
        }
        if self.holders(observed).next().is_some() {
            return Err(Refusal::Occupied);
        }
        let target = self
            .seen(observed)
            .find(|seen| {
                seen.spec.is_durable()
                    && seen.spec.is_writable()
                    && seen.observed == Observation::Empty
            })
            .ok_or(Refusal::NoDurableSink)?;
        let cache = self
            .seen(observed)
            .filter(|seen| seen.spec.is_writable() && !seen.spec.is_durable())
            .filter(|seen| matches!(seen.observed, Observation::Empty | Observation::Rejected(_)))
            .fold(SourceSet::EMPTY, |set, seen| set.with(seen.id));
        Ok(Mint {
            target: target.id,
            cache,
        })
    }

    fn missing(observed: &[Observation; N], vault: Vault) -> Refusal {
        match vault {
            Vault::Unsealed => Refusal::Vacant,
            Vault::Sealed if observed.contains(&Observation::Unreachable) => Refusal::Unavailable,
            Vault::Sealed => Refusal::Lost,
        }
    }

    fn seen<'a>(&'a self, observed: &'a [Observation; N]) -> impl Iterator<Item = Seen> + 'a {
        self.specs
            .iter()
            .zip(observed)
            .zip(0u8..)
            .map(|((spec, observed), index)| Seen {
                id: SourceId::new(index),
                spec: *spec,
                observed: *observed,
            })
    }

    fn ranked<'a>(
        &'a self,
        observed: &'a [Observation; N],
    ) -> impl Iterator<Item = (Seen, Fingerprint)> + 'a {
        let durable = self
            .holders(observed)
            .filter(|(seen, _)| seen.spec.is_durable());
        durable.chain(
            self.holders(observed)
                .filter(|(seen, _)| !seen.spec.is_durable()),
        )
    }

    fn holders<'a>(
        &'a self,
        observed: &'a [Observation; N],
    ) -> impl Iterator<Item = (Seen, Fingerprint)> + 'a {
        self.seen(observed).filter_map(|seen| match seen.observed {
            Observation::Holds(fp) => Some((seen, fp)),
            Observation::Empty | Observation::Unreachable | Observation::Rejected(_) => None,
        })
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lost => f.write_str("the vault is sealed and no source holds its key"),
            Self::Unavailable => f.write_str(
                "the vault is sealed, no reachable source holds its key, and one is silent",
            ),
            Self::Divergent { a, b } => write!(
                f,
                "sources {} and {} hold different keys over a sealed vault",
                a.index(),
                b.index()
            ),
            Self::VolatileOnly => f.write_str("the only copy of the key dies with the next reboot"),
            Self::NoDurableSink => f.write_str("no durable source accepts a new key"),
            Self::Sealed => f.write_str("the vault is already sealed under another key"),
            Self::Occupied => f.write_str("a source already holds a key"),
            Self::Vacant => f.write_str("nothing is sealed and no source holds a key"),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDurableSource => f.write_str("a ladder needs at least one durable source"),
        }
    }
}

impl core::error::Error for Refusal {}
impl core::error::Error for ConfigError {}

#[cfg(test)]
mod tests;
