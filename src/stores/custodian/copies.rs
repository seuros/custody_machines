use super::{Custodian, Status, Survey};
use crate::stores::{Sighting, Source, SourceError};
use crate::{Custody, Fingerprint, Observation, Open, SourceId, Vault};

impl<const N: usize> Custodian<N> {
    /// Carry out the copies, falling through to the next durable source when
    /// one refuses the write, and answer the custody that results.
    ///
    /// Over sealed data, the key is proven before any durable copy, and before
    /// any copy at all while a source is unreachable (a refused write makes it
    /// so mid-decision): a durable copy of the wrong key could never be
    /// replaced by the right one. Caches go first, so their failures come
    /// before the durable write. `None` when the proof fails: nothing more is
    /// copied.
    pub(super) fn copy_all(
        &self,
        survey: &mut Survey<N>,
        vault: Vault,
        open: Open,
        secret: &[u8],
        mut prove: impl FnMut() -> bool,
    ) -> Option<Custody> {
        let mut plan = open;
        let mut attempted: Vec<SourceId> = Vec::new();
        for _ in 0..=N {
            let mut fresh: Vec<SourceId> = plan
                .copy_to
                .iter()
                .filter(|id| !attempted.contains(id))
                .collect();
            fresh.sort_by_key(|id| {
                self.ladder
                    .spec(*id)
                    .is_some_and(crate::SourceSpec::is_durable)
            });
            if fresh.is_empty() {
                break;
            }
            for target in fresh {
                let durable = self
                    .ladder
                    .spec(target)
                    .is_some_and(crate::SourceSpec::is_durable);
                let unreachable = survey.observed.contains(&Observation::Unreachable);
                let doubt = vault == Vault::Sealed && (durable || unreachable);
                if doubt && !prove() {
                    return None;
                }
                attempted.push(target);
                self.copy(survey, target, secret, plan.fingerprint);
            }
            match self.ladder.open(&survey.observed, vault) {
                Ok(next) => plan = next,
                Err(_) => break,
            }
        }
        let doubt = vault == Vault::Sealed && survey.observed.contains(&Observation::Unreachable);
        if doubt && !prove() {
            return None;
        }
        Some(plan.custody)
    }

    pub(super) fn status_of(survey: &Survey<N>, id: SourceId) -> String {
        survey.statuses.get(id.index()).map_or_else(
            || "no durable source accepted the key".to_owned(),
            ToString::to_string,
        )
    }

    /// Store the key in `target`. A source that refuses the write counts as
    /// unreachable for the rest of this decision, so the ladder moves past it.
    pub(super) fn copy(
        &self,
        survey: &mut Survey<N>,
        target: SourceId,
        secret: &[u8],
        fp: Fingerprint,
    ) -> bool {
        let Some(source) = self.sources.get(target.index()) else {
            return false;
        };
        match self.store(source.as_ref(), secret, fp) {
            Ok(()) => {
                Self::set(survey, target, Observation::Holds(fp), Status::Copied);
                true
            }
            Err(error) => {
                let status = Status::CopyFailed(error.to_string());
                Self::set(survey, target, Observation::Unreachable, status);
                false
            }
        }
    }

    pub(super) fn store(
        &self,
        source: &dyn Source,
        secret: &[u8],
        fp: Fingerprint,
    ) -> Result<(), SourceError> {
        source.write(secret)?;
        match source.read() {
            Sighting::Holds(back) if self.fingerprint(&back) == fp => Ok(()),
            Sighting::Holds(_) => Err(SourceError::new("read back a different key")),
            Sighting::Empty => Err(SourceError::new("read back no key")),
            Sighting::Unreachable(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests;
