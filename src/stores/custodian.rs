use std::error::Error;
use std::fmt;

use sha2::{Digest, Sha256};

use super::{MAX_KEY_BYTES, Report, Secret, Sighting, Source, SourceError, Status};
use crate::{ConfigError, Custody, Fingerprint, Ladder, Observation, Refusal, SourceId, Vault};

/// Reads every source, lets the [`Ladder`] decide, and carries out the copies.
///
/// It takes no lock, and both [`Custodian::open`] and
/// [`Custodian::open_or_mint`] write: callers that share sources with another
/// process hold their own lock around every call. Each write is read back
/// before the custodian counts it.
pub struct Custodian<const N: usize> {
    ladder: Ladder<N>,
    sources: [Box<dyn Source>; N],
    domain: &'static str,
}

/// A key the custodian vouches for.
pub struct Key {
    secret: Secret,
    custody: Custody,
    source: String,
    report: Report,
}

/// Why the custodian could not produce a key.
#[derive(Debug)]
pub enum CustodyError {
    /// The kernel refused; the report says what every source answered.
    Refused {
        /// The kernel's answer.
        refusal: Refusal,
        /// What every source answered.
        report: Report,
    },
    /// A fresh key could not be stored in its durable source.
    Mint {
        /// The source that failed.
        source: String,
        /// Why.
        error: SourceError,
    },
}

struct Survey<const N: usize> {
    held: [Option<Secret>; N],
    observed: [Observation; N],
    statuses: [Status; N],
}

impl<const N: usize> Custodian<N> {
    /// A custodian over `sources`, most preferred first. `domain` separates
    /// this application's fingerprints from any other's.
    ///
    /// # Errors
    ///
    /// [`ConfigError::NoDurableSource`] when every source is volatile.
    pub fn new(domain: &'static str, sources: [Box<dyn Source>; N]) -> Result<Self, ConfigError> {
        let ladder = Ladder::new(sources.each_ref().map(|source| source.spec()))?;
        Ok(Self {
            ladder,
            sources,
            domain,
        })
    }

    /// The fingerprint the custodian gives `key`.
    #[must_use]
    pub fn fingerprint(&self, key: &[u8]) -> Fingerprint {
        let mut hasher = Sha256::new();
        hasher.update(self.domain.as_bytes());
        hasher.update([0]);
        hasher.update(key);
        hasher.finalize().into()
    }

    /// Open the existing key, copying it where the ladder says.
    ///
    /// `opens` answers whether a key opens the vault. Over a sealed vault it
    /// is asked when sources disagree, or when a source is unreachable and
    /// the visible key might not be the one that sealed it.
    ///
    /// # Errors
    ///
    /// [`CustodyError::Refused`] with every source's answer.
    pub fn open(
        &self,
        vault: Vault,
        opens: impl FnMut(&[u8]) -> bool,
    ) -> Result<Key, CustodyError> {
        let mut survey = self.survey();
        self.resolve(&mut survey, vault, opens)
    }

    /// Open the existing key, or mint one with `generate` when nothing is
    /// sealed and no source holds a key.
    ///
    /// # Errors
    ///
    /// [`CustodyError::Refused`], or [`CustodyError::Mint`] when the fresh
    /// key could not be stored and read back.
    pub fn open_or_mint(
        &self,
        vault: Vault,
        opens: impl FnMut(&[u8]) -> bool,
        generate: impl FnOnce() -> Secret,
    ) -> Result<Key, CustodyError> {
        let mut survey = self.survey();
        match self.resolve(&mut survey, vault, opens) {
            Err(CustodyError::Refused {
                refusal: Refusal::Vacant,
                ..
            }) => self.mint(&mut survey, vault, generate),
            other => other,
        }
    }

    fn survey(&self) -> Survey<N> {
        let mut held = [const { None }; N];
        let mut observed = [Observation::Empty; N];
        let mut statuses = [const { Status::Empty }; N];
        for (index, source) in self.sources.iter().enumerate() {
            let (Some(held), Some(observed), Some(status)) = (
                held.get_mut(index),
                observed.get_mut(index),
                statuses.get_mut(index),
            ) else {
                continue;
            };
            match source.read() {
                Sighting::Holds(key) => {
                    *observed = Observation::Holds(self.fingerprint(&key));
                    *status = Status::Holds;
                    *held = Some(key);
                }
                Sighting::Empty => {}
                Sighting::Unreachable(error) => {
                    *observed = Observation::Unreachable;
                    *status = Status::Unreachable(error.to_string());
                }
            }
        }
        Survey {
            held,
            observed,
            statuses,
        }
    }

    fn resolve(
        &self,
        survey: &mut Survey<N>,
        vault: Vault,
        mut opens: impl FnMut(&[u8]) -> bool,
    ) -> Result<Key, CustodyError> {
        let mut proven: Vec<Fingerprint> = Vec::new();
        let mut diverged = false;
        for _ in 0..=N {
            match self.ladder.open(&survey.observed, vault) {
                Ok(open) => {
                    let Some(secret) = survey.held.get(open.authority.index()).cloned().flatten()
                    else {
                        break;
                    };
                    let doubt = diverged
                        || (vault == Vault::Sealed
                            && survey.observed.contains(&Observation::Unreachable));
                    if doubt && !Self::proves(&mut proven, open.fingerprint, &secret, &mut opens) {
                        Self::set_aside(survey, open.fingerprint, &Status::Rejected);
                        continue;
                    }
                    let fingerprint = open.fingerprint;
                    let prove = || Self::proves(&mut proven, fingerprint, &secret, &mut opens);
                    let Some(custody) = self.copy_all(survey, vault, open, &secret, prove) else {
                        Self::set_aside(survey, fingerprint, &Status::Rejected);
                        continue;
                    };
                    return Ok(Key {
                        secret,
                        custody,
                        source: self.name(open.authority),
                        report: self.report(survey),
                    });
                }
                Err(Refusal::Divergent { a, b }) => {
                    diverged = true;
                    let [first, second] = [a, b].map(|id| {
                        let fp = match survey.observed.get(id.index()) {
                            Some(Observation::Holds(fp)) => Some(*fp),
                            _ => None,
                        }?;
                        let held = survey.held.get(id.index()).cloned().flatten();
                        let opened =
                            held.is_some_and(|key| Self::proves(&mut proven, fp, &key, &mut opens));
                        Some((fp, opened))
                    });
                    for (fp, opened) in [first, second].into_iter().flatten() {
                        if !opened {
                            Self::set_aside(survey, fp, &Status::Rejected);
                        }
                    }
                    if let (Some((_, true)), Some((fp, true))) = (first, second) {
                        Self::set_aside(survey, fp, &Status::Alternate);
                    }
                }
                Err(refusal) => return Err(self.refused(refusal, survey)),
            }
        }
        debug_assert!(false, "every divergence round rejects a holder");
        Err(self.refused(Refusal::Unavailable, survey))
    }

    fn mint(
        &self,
        survey: &mut Survey<N>,
        vault: Vault,
        generate: impl FnOnce() -> Secret,
    ) -> Result<Key, CustodyError> {
        let first = self
            .ladder
            .mint(&survey.observed, vault)
            .map_err(|refusal| self.refused(refusal, survey))?;
        let secret = generate();
        let failed = |error| CustodyError::Mint {
            source: self.name(first.target),
            error,
        };
        if secret.is_empty() {
            return Err(failed(SourceError::new("the generated key is empty")));
        }
        if u64::try_from(secret.len())
            .ok()
            .is_none_or(|len| len > MAX_KEY_BYTES)
        {
            return Err(failed(SourceError::new(format!(
                "the generated key is larger than {MAX_KEY_BYTES} bytes"
            ))));
        }
        let fingerprint = self.fingerprint(&secret);
        let mut mint = first;
        while !self.copy(survey, mint.target, &secret, fingerprint) {
            let refused = mint.target;
            match self.ladder.mint(&survey.observed, vault) {
                Ok(next) => mint = next,
                Err(_) => {
                    return Err(CustodyError::Mint {
                        source: self.name(refused),
                        error: SourceError::new(Self::status_of(survey, refused)),
                    });
                }
            }
        }
        for cache in mint.cache.iter() {
            self.copy(survey, cache, &secret, fingerprint);
        }
        Ok(Key {
            secret,
            custody: Custody::Durable,
            source: self.name(mint.target),
            report: self.report(survey),
        })
    }

    fn proves(
        proven: &mut Vec<Fingerprint>,
        fp: Fingerprint,
        key: &[u8],
        opens: &mut impl FnMut(&[u8]) -> bool,
    ) -> bool {
        if proven.contains(&fp) {
            return true;
        }
        let opened = opens(key);
        if opened {
            proven.push(fp);
        }
        opened
    }

    fn set_aside(survey: &mut Survey<N>, fp: Fingerprint, why: &Status) {
        for index in 0..N {
            if survey.observed.get(index) == Some(&Observation::Holds(fp))
                && let (Some(slot), Some(status)) = (
                    survey.observed.get_mut(index),
                    survey.statuses.get_mut(index),
                )
            {
                *slot = Observation::Rejected(fp);
                *status = why.clone();
            }
        }
    }

    fn set(survey: &mut Survey<N>, id: SourceId, observed: Observation, status: Status) {
        if let (Some(slot), Some(status_slot)) = (
            survey.observed.get_mut(id.index()),
            survey.statuses.get_mut(id.index()),
        ) {
            *slot = observed;
            *status_slot = status;
        }
    }

    fn name(&self, id: SourceId) -> String {
        self.sources
            .get(id.index())
            .map_or_else(String::new, |source| source.name().to_owned())
    }

    fn report(&self, survey: &Survey<N>) -> Report {
        let entries = self
            .sources
            .iter()
            .zip(&survey.statuses)
            .map(|(source, status)| (source.name().to_owned(), status.clone()))
            .collect();
        Report::new(entries)
    }

    fn refused(&self, refusal: Refusal, survey: &Survey<N>) -> CustodyError {
        CustodyError::Refused {
            refusal,
            report: self.report(survey),
        }
    }
}

impl Key {
    /// The key bytes.
    #[must_use]
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Whether a durable source holds the key, after the copies.
    #[must_use]
    pub const fn custody(&self) -> Custody {
        self.custody
    }

    /// The source the key came from.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// What every source answered, and the copies made.
    #[must_use]
    pub const fn report(&self) -> &Report {
        &self.report
    }

    /// Whether data may be sealed under this key.
    ///
    /// # Errors
    ///
    /// [`Refusal::VolatileOnly`] when no durable source holds the key.
    pub fn permit_write(&self) -> Result<(), CustodyError> {
        match self.custody {
            Custody::Durable => Ok(()),
            Custody::VolatileOnly => Err(CustodyError::Refused {
                refusal: Refusal::VolatileOnly,
                report: self.report.clone(),
            }),
        }
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("custody", &self.custody)
            .field("source", &self.source)
            .field("report", &self.report)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for CustodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused { refusal, report } => write!(f, "{refusal} [{report}]"),
            Self::Mint { source, error } => {
                write!(f, "cannot store a new key in {source}: {error}")
            }
        }
    }
}

impl Error for CustodyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Refused { refusal, .. } => Some(refusal),
            Self::Mint { error, .. } => Some(error),
        }
    }
}

mod copies;

#[cfg(test)]
mod tests;
