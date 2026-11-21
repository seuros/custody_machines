use super::*;
use crate::stores::testing::MemorySource;
use crate::stores::{CredentialsDir, KeyFile};

pub(super) fn generate(key: &'static [u8]) -> impl FnOnce() -> Secret {
    move || Secret::new(key.to_vec())
}

pub(super) fn proven(_: &[u8]) -> bool {
    true
}

pub(super) fn never(_: &[u8]) -> bool {
    panic!("asked to verify without a divergence")
}

pub(super) struct Host {
    pub(super) provisioned: MemorySource,
    pub(super) service: MemorySource,
    pub(super) file: MemorySource,
    pub(super) cache: MemorySource,
}

impl Host {
    pub(super) fn new() -> Self {
        Self {
            provisioned: MemorySource::provisioned("credential"),
            service: MemorySource::durable("secret service"),
            file: MemorySource::durable("key file"),
            cache: MemorySource::cache("kernel keyring"),
        }
    }

    pub(super) fn custodian(&self) -> Custodian<4> {
        Custodian::new(
            "custody-test",
            [
                Box::new(self.provisioned.clone()),
                Box::new(self.service.clone()),
                Box::new(self.file.clone()),
                Box::new(self.cache.clone()),
            ],
        )
        .unwrap()
    }
}

#[test]
fn first_run_mints_into_durable_and_caches() {
    let host = Host::new();
    host.service.set_unreachable(true);
    let key = host
        .custodian()
        .open_or_mint(Vault::Unsealed, never, generate(b"fresh"))
        .unwrap();
    assert_eq!(key.secret(), b"fresh");
    assert_eq!(key.custody(), Custody::Durable);
    assert_eq!(key.source(), "key file");
    assert!(host.file.holds(b"fresh"));
    assert!(host.cache.holds(b"fresh"));
    assert_eq!(host.provisioned.writes(), 0);
}

#[test]
fn a_reboot_wipes_the_cache_and_the_vault_still_opens() {
    let host = Host::new();
    host.service.set_unreachable(true);
    host.custodian()
        .open_or_mint(Vault::Unsealed, never, generate(b"k"))
        .unwrap();
    host.cache.wipe();
    let key = host.custodian().open(Vault::Sealed, proven).unwrap();
    assert_eq!(key.secret(), b"k");
    assert!(host.cache.holds(b"k"));
}

#[test]
fn a_cache_only_key_from_the_old_layout_is_rescued() {
    let host = Host::new();
    host.service.set_unreachable(true);
    host.cache.put(b"legacy");
    let key = host.custodian().open(Vault::Sealed, proven).unwrap();
    assert_eq!(key.custody(), Custody::Durable);
    assert!(host.file.holds(b"legacy"));
    assert!(key.permit_write().is_ok());
}

#[test]
fn a_failed_rescue_leaves_the_key_volatile_and_writes_refused() {
    let host = Host::new();
    host.service.set_unreachable(true);
    host.file.refuse_writes(true);
    host.cache.put(b"legacy");
    let key = host.custodian().open(Vault::Sealed, proven).unwrap();
    assert_eq!(key.custody(), Custody::VolatileOnly);
    let error = key.permit_write().unwrap_err();
    assert!(error.to_string().contains("copy failed"), "{error}");
}

#[test]
fn a_sealed_vault_with_a_silent_source_is_unavailable_not_lost() {
    let host = Host::new();
    host.service.set_unreachable(true);
    let error = host
        .custodian()
        .open_or_mint(Vault::Sealed, never, generate(b"x"))
        .unwrap_err();
    let CustodyError::Refused { refusal, .. } = &error else {
        panic!("{error}")
    };
    assert_eq!(*refusal, Refusal::Unavailable);
    assert!(
        error.to_string().contains("secret service: unreachable"),
        "{error}"
    );
    assert_eq!(host.file.writes(), 0);
}

#[test]
fn a_sealed_vault_with_every_source_empty_is_lost() {
    let host = Host::new();
    let error = host.custodian().open(Vault::Sealed, never).unwrap_err();
    assert!(matches!(
        error,
        CustodyError::Refused {
            refusal: Refusal::Lost,
            ..
        }
    ));
}

#[test]
fn divergent_keys_are_settled_by_the_one_that_opens_the_vault() {
    let host = Host::new();
    host.file.put(b"stale");
    host.cache.put(b"right");
    let key = host
        .custodian()
        .open(Vault::Sealed, |key| key == b"right")
        .unwrap();
    assert_eq!(key.secret(), b"right");
    assert_eq!(key.custody(), Custody::Durable);
    assert!(host.service.holds(b"right"), "rescued");
    assert!(host.file.holds(b"stale"), "never overwritten");
    let rejected = key
        .report()
        .entries()
        .any(|(name, status)| name == "key file" && *status == Status::Rejected);
    assert!(rejected, "{}", key.report());
}

#[test]
fn divergent_keys_that_both_fail_are_lost() {
    let host = Host::new();
    host.file.put(b"one");
    host.cache.put(b"two");
    let error = host.custodian().open(Vault::Sealed, |_| false).unwrap_err();
    assert!(
        matches!(
            error,
            CustodyError::Refused {
                refusal: Refusal::Lost,
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn a_better_source_appearing_receives_the_key() {
    let host = Host::new();
    host.file.put(b"k");
    let key = host.custodian().open(Vault::Sealed, proven).unwrap();
    assert_eq!(key.source(), "key file");
    assert!(host.service.holds(b"k"));
    assert_eq!(
        host.custodian()
            .open(Vault::Sealed, proven)
            .unwrap()
            .source(),
        "secret service"
    );
}

#[test]
fn a_mint_that_cannot_be_stored_fails_and_caches_nothing() {
    let host = Host::new();
    host.service.set_unreachable(true);
    host.file.refuse_writes(true);
    let error = host
        .custodian()
        .open_or_mint(Vault::Unsealed, never, generate(b"k"))
        .unwrap_err();
    assert!(matches!(error, CustodyError::Mint { .. }), "{error}");
    assert!(host.cache.held().is_none());
}

#[test]
fn real_files_survive_a_new_process_view() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets/vault.key");
    let cache = MemorySource::cache("cache");
    let custodian = |cache: &MemorySource| {
        Custodian::new(
            "custody-test",
            [
                Box::new(CredentialsDir::at(dir.path().join("creds"), "vault")) as Box<dyn Source>,
                Box::new(KeyFile::new(&path)),
                Box::new(cache.clone()),
            ],
        )
        .unwrap()
    };
    custodian(&cache)
        .open_or_mint(Vault::Unsealed, never, generate(b"disk"))
        .unwrap();
    let rebooted = MemorySource::cache("cache");
    let key = custodian(&rebooted).open(Vault::Sealed, never).unwrap();
    assert_eq!(key.secret(), b"disk");
    assert!(rebooted.holds(b"disk"));
}

#[test]
fn errors_carry_their_cause_in_the_message() {
    let error = SourceError::caused_by("cannot connect", std::io::Error::other("KeyRevoked"));
    assert_eq!(error.to_string(), "cannot connect: KeyRevoked");
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn a_fingerprint_that_failed_is_rejected_everywhere() {
    let host = Host::new();
    host.service.put(b"wrong");
    host.file.put(b"other");
    host.cache.put(b"wrong");
    let error = host.custodian().open(Vault::Sealed, |_| false).unwrap_err();
    assert!(
        matches!(
            error,
            CustodyError::Refused {
                refusal: Refusal::Lost,
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn the_last_candidate_after_a_divergence_is_still_proven() {
    let host = Host::new();
    host.service.put(b"one");
    host.file.put(b"two");
    host.cache.put(b"three");
    let error = host
        .custodian()
        .open(Vault::Sealed, |key| key == b"nope")
        .unwrap_err();
    assert!(
        matches!(
            error,
            CustodyError::Refused {
                refusal: Refusal::Lost,
                ..
            }
        ),
        "{error}"
    );
    let key = host
        .custodian()
        .open(Vault::Sealed, |key| key == b"three")
        .unwrap();
    assert_eq!(key.secret(), b"three");
}

#[test]
fn a_write_that_does_not_stick_is_not_counted() {
    let host = Host::new();
    host.service.set_unreachable(true);
    host.file.lose_writes(true);
    host.cache.put(b"legacy");
    let key = host.custodian().open(Vault::Sealed, proven).unwrap();
    assert_eq!(key.custody(), Custody::VolatileOnly);
    assert!(
        key.report().to_string().contains("read back no key"),
        "{}",
        key.report()
    );
}

#[test]
fn a_key_minted_while_a_store_was_silent_wins_when_it_returns() {
    let host = Host::new();
    host.service.put(b"orphaned");
    host.service.set_unreachable(true);
    let minted = host
        .custodian()
        .open_or_mint(Vault::Unsealed, never, generate(b"new"))
        .unwrap();
    host.service.set_unreachable(false);
    let key = host
        .custodian()
        .open(Vault::Sealed, |key| key == minted.secret())
        .unwrap();
    assert_eq!(key.secret(), b"new");
    assert!(
        host.service.holds(b"orphaned"),
        "a rejected durable copy is left alone"
    );
}

#[test]
fn debug_output_never_shows_key_bytes() {
    let host = Host::new();
    host.file.put(b"hunter2");
    let shown = format!("{:?} {:?}", host.file, host.file.read());
    assert!(!shown.contains("104"), "{shown}");
    let key = host.custodian().open(Vault::Sealed, proven).unwrap();
    assert!(!format!("{key:?}").contains("104"));
}

#[test]
fn two_keys_that_both_open_settle_on_the_preferred_one() {
    let host = Host::new();
    host.file.put(b"first");
    host.cache.put(b"second");
    let key = host.custodian().open(Vault::Sealed, |_| true).unwrap();
    assert_eq!(key.secret(), b"first");
    assert!(
        host.cache.holds(b"first"),
        "the cache follows the authority"
    );
}

#[test]
fn an_unusable_generated_key_is_never_written() {
    let host = Host::new();
    host.service.set_unreachable(true);
    for bad in [Vec::new(), vec![0; 64 * 1024 + 1]] {
        let generate = move || Secret::new(bad);
        let error = host
            .custodian()
            .open_or_mint(Vault::Unsealed, never, generate)
            .unwrap_err();
        assert!(matches!(error, CustodyError::Mint { .. }), "{error}");
        assert_eq!(host.file.writes(), 0);
    }
}

#[test]
fn two_opening_keys_prefer_durable_over_an_earlier_cache() {
    let cache = MemorySource::cache("cache");
    let file = MemorySource::durable("key file");
    cache.put(b"cached");
    file.put(b"durable");
    let custodian = Custodian::new(
        "custody-test",
        [Box::new(cache) as Box<dyn Source>, Box::new(file)],
    )
    .unwrap();
    let key = custodian.open(Vault::Sealed, |_| true).unwrap();
    assert_eq!(key.secret(), b"durable");
    assert_eq!(key.custody(), Custody::Durable);
}

#[test]
fn a_lone_key_is_proven_while_another_source_is_silent() {
    let host = Host::new();
    host.service.set_unreachable(true);
    host.file.put(b"stale");
    let error = host
        .custodian()
        .open(Vault::Sealed, |key| key == b"real")
        .unwrap_err();
    assert!(matches!(
        error,
        CustodyError::Refused {
            refusal: Refusal::Unavailable,
            ..
        }
    ));
    let key = host
        .custodian()
        .open(Vault::Sealed, |key| key == b"stale")
        .unwrap();
    assert_eq!(key.secret(), b"stale");
}
