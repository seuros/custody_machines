use crate::stores::custodian::tests::{Host, generate, never, proven};
use crate::stores::testing::MemorySource;
use crate::stores::{Custodian, CustodyError, Source};
use crate::{Custody, Vault};

#[test]
fn a_durable_source_that_refuses_the_mint_falls_through_to_the_next() {
    let host = Host::new();
    host.service.refuse_writes(true);
    let key = host
        .custodian()
        .open_or_mint(Vault::Unsealed, never, generate(b"k"))
        .unwrap();
    assert_eq!(key.source(), "key file");
    assert_eq!(key.custody(), Custody::Durable);
    assert!(host.file.holds(b"k"));
    assert!(
        key.report()
            .to_string()
            .contains("secret service: copy failed"),
        "{}",
        key.report()
    );
}

#[test]
fn a_rescue_falls_through_a_durable_source_that_refuses_the_write() {
    let host = Host::new();
    host.service.refuse_writes(true);
    host.cache.put(b"legacy");
    let key = host.custodian().open(Vault::Sealed, proven).unwrap();
    assert_eq!(key.custody(), Custody::Durable);
    assert!(host.file.holds(b"legacy"));
}

#[test]
fn a_mint_no_durable_source_accepts_names_the_last_refusal() {
    let host = Host::new();
    host.service.refuse_writes(true);
    host.file.refuse_writes(true);
    let error = host
        .custodian()
        .open_or_mint(Vault::Unsealed, never, generate(b"k"))
        .unwrap_err();
    assert!(matches!(error, CustodyError::Mint { .. }), "{error}");
    assert!(error.to_string().contains("key file"), "{error}");
    assert!(host.cache.held().is_none());
}

#[test]
fn a_refused_write_makes_the_key_prove_itself_before_it_is_rescued() {
    let host = Host::new();
    host.service.refuse_writes(true);
    host.cache.put(b"stale");
    let error = host
        .custodian()
        .open(Vault::Sealed, |key| key == b"real")
        .unwrap_err();
    assert!(matches!(error, CustodyError::Refused { .. }), "{error}");
    assert!(
        host.file.held().is_none(),
        "an unproven key is never rescued"
    );
    let key = host
        .custodian()
        .open(Vault::Sealed, |key| key == b"stale")
        .unwrap();
    assert_eq!(key.custody(), Custody::Durable);
    assert!(host.file.holds(b"stale"));
}

#[test]
fn a_failed_cache_write_stops_the_rest_of_the_round_until_the_key_is_proven() {
    let failing = MemorySource::cache("failing cache");
    failing.refuse_writes(true);
    let file = MemorySource::durable("key file");
    let stale = MemorySource::cache("stale cache");
    stale.put(b"stale");
    let custodian = Custodian::new(
        "custody-test",
        [
            Box::new(failing) as Box<dyn Source>,
            Box::new(file.clone()),
            Box::new(stale),
        ],
    )
    .unwrap();
    assert!(custodian.open(Vault::Sealed, |key| key == b"real").is_err());
    assert!(
        file.held().is_none(),
        "nothing durable is written before the proof"
    );
}

#[test]
fn a_failed_last_copy_still_makes_the_key_prove_itself() {
    let file = MemorySource::durable("key file");
    file.put(b"stale");
    let cache = MemorySource::cache("cache");
    cache.refuse_writes(true);
    let custodian = Custodian::new(
        "custody-test",
        [Box::new(file) as Box<dyn Source>, Box::new(cache)],
    )
    .unwrap();
    assert!(custodian.open(Vault::Sealed, |key| key == b"real").is_err());
    let key = custodian
        .open(Vault::Sealed, |key| key == b"stale")
        .unwrap();
    assert_eq!(key.secret(), b"stale");
}

#[test]
fn caches_are_written_before_the_durable_target_so_a_failure_comes_first() {
    let file = MemorySource::durable("key file");
    let failing = MemorySource::cache("failing cache");
    failing.refuse_writes(true);
    let stale = MemorySource::cache("stale cache");
    stale.put(b"stale");
    let custodian = Custodian::new(
        "custody-test",
        [
            Box::new(file.clone()) as Box<dyn Source>,
            Box::new(failing),
            Box::new(stale),
        ],
    )
    .unwrap();
    assert!(custodian.open(Vault::Sealed, |key| key == b"real").is_err());
    assert!(
        file.held().is_none(),
        "the durable copy waits for the proof"
    );
}

#[test]
fn a_key_is_proven_before_it_is_moved_into_durable_storage() {
    let host = Host::new();
    host.cache.put(b"stale");
    host.service.set_unreachable(false);
    assert!(
        host.custodian()
            .open(Vault::Sealed, |key| key == b"real")
            .is_err()
    );
    assert!(host.service.held().is_none() && host.file.held().is_none());
}
