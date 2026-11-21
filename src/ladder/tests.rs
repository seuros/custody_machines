use super::*;
use crate::source::{Access, Durability};
use Observation::{Empty, Holds, Rejected, Unreachable};

const K1: Fingerprint = [1; 32];
const K2: Fingerprint = [2; 32];

fn id(index: u8) -> SourceId {
    SourceId::new(index)
}

fn set(ids: &[u8]) -> SourceSet {
    ids.iter()
        .fold(SourceSet::EMPTY, |set, index| set.with(id(*index)))
}

fn linux() -> Ladder<4> {
    Ladder::new([
        SourceSpec::provisioned(),
        SourceSpec::durable(),
        SourceSpec::durable(),
        SourceSpec::cache(),
    ])
    .unwrap()
}

#[test]
fn a_ladder_needs_a_durable_source() {
    let all_cache = Ladder::new([SourceSpec::cache(), SourceSpec::cache()]);
    assert_eq!(all_cache, Err(ConfigError::NoDurableSource));
}

#[test]
fn a_wiped_cache_still_opens_from_durable() {
    let open = linux()
        .open(&[Empty, Unreachable, Holds(K1), Empty], Vault::Sealed)
        .unwrap();
    assert_eq!(open.authority, id(2));
    assert_eq!(open.custody, Custody::Durable);
    assert_eq!(open.copy_to, set(&[3]));
    assert_eq!(open.permit_write(), Ok(()));
}

#[test]
fn a_cache_only_key_is_rescued_into_durable() {
    let open = linux()
        .open(&[Empty, Unreachable, Empty, Holds(K1)], Vault::Sealed)
        .unwrap();
    assert_eq!(open.authority, id(3));
    assert_eq!(open.custody, Custody::VolatileOnly);
    assert_eq!(open.copy_to, set(&[2]));
    assert_eq!(open.permit_write(), Err(Refusal::VolatileOnly));
}

#[test]
fn empty_is_not_absent_while_a_source_is_unreachable() {
    let observed = [Empty, Unreachable, Empty, Empty];
    assert_eq!(
        linux().open(&observed, Vault::Sealed),
        Err(Refusal::Unavailable)
    );
    assert_eq!(
        linux().open(&[Empty, Empty, Empty, Unreachable], Vault::Sealed),
        { Err(Refusal::Unavailable) }
    );
}

#[test]
fn a_sealed_vault_with_every_source_empty_is_lost() {
    assert_eq!(linux().open(&[Empty; 4], Vault::Sealed), Err(Refusal::Lost));
}

#[test]
fn an_unsealed_vault_with_no_key_is_vacant_and_mints_into_durable() {
    let observed = [Empty, Unreachable, Empty, Empty];
    assert_eq!(
        linux().open(&observed, Vault::Unsealed),
        Err(Refusal::Vacant)
    );
    let mint = linux().mint(&observed, Vault::Unsealed).unwrap();
    assert_eq!(mint.target, id(2));
    assert_eq!(mint.cache, set(&[3]));
}

#[test]
fn mint_refuses_sealed_occupied_and_sinkless() {
    assert_eq!(
        linux().mint(&[Empty; 4], Vault::Sealed),
        Err(Refusal::Sealed)
    );
    let occupied = [Empty, Empty, Empty, Holds(K1)];
    assert_eq!(
        linux().mint(&occupied, Vault::Unsealed),
        Err(Refusal::Occupied)
    );
    let sinkless = [Empty, Unreachable, Unreachable, Empty];
    assert_eq!(
        linux().mint(&sinkless, Vault::Unsealed),
        Err(Refusal::NoDurableSink)
    );
}

#[test]
fn a_key_moves_up_when_a_better_source_appears() {
    let open = linux()
        .open(&[Empty, Empty, Holds(K1), Holds(K1)], Vault::Sealed)
        .unwrap();
    assert_eq!(open.authority, id(2));
    assert_eq!(open.copy_to, set(&[1]));
}

#[test]
fn a_provisioned_key_wins_and_is_never_written() {
    let open = linux()
        .open(&[Holds(K1), Empty, Empty, Empty], Vault::Sealed)
        .unwrap();
    assert_eq!(open.authority, id(0));
    assert_eq!(open.copy_to, set(&[3]));
}

#[test]
fn divergent_keys_over_sealed_data_are_refused_until_one_is_rejected() {
    let observed = [Empty, Holds(K1), Empty, Holds(K2)];
    let divergent = Refusal::Divergent { a: id(1), b: id(3) };
    assert_eq!(linux().open(&observed, Vault::Sealed), Err(divergent));
    let open = linux()
        .open(&[Empty, Holds(K1), Empty, Rejected(K2)], Vault::Sealed)
        .unwrap();
    assert_eq!(open.authority, id(1));
    assert_eq!(open.copy_to, set(&[3]));
}

#[test]
fn divergence_ranks_durable_holders_before_caches() {
    let ladder = Ladder::new([SourceSpec::cache(), SourceSpec::durable()]).unwrap();
    let divergent = Refusal::Divergent { a: id(1), b: id(0) };
    assert_eq!(
        ladder.open(&[Holds(K1), Holds(K2)], Vault::Sealed),
        Err(divergent)
    );
}

#[test]
fn a_rejected_durable_copy_is_never_overwritten() {
    let open = linux()
        .open(&[Empty, Rejected(K2), Holds(K1), Empty], Vault::Sealed)
        .unwrap();
    assert_eq!(open.authority, id(2));
    assert_eq!(open.copy_to, set(&[3]));
}

#[test]
fn unsealed_divergence_prefers_durable_and_refreshes_caches() {
    let open = linux()
        .open(&[Empty, Empty, Holds(K1), Holds(K2)], Vault::Unsealed)
        .unwrap();
    assert_eq!(open.fingerprint, K1);
    assert_eq!(open.copy_to, set(&[1, 3]));
}

const KINDS: [Observation; 6] = [
    Empty,
    Unreachable,
    Holds(K1),
    Holds(K2),
    Rejected(K1),
    Rejected(K2),
];
const SPECS: [SourceSpec; 3] = [
    SourceSpec::durable(),
    SourceSpec::provisioned(),
    SourceSpec::cache(),
];

fn ladders() -> impl Iterator<Item = Ladder<3>> {
    (0..27usize).filter_map(|n| {
        let pick = |digit: u32| SPECS[(n / 3usize.pow(digit)) % 3];
        Ladder::new([pick(0), pick(1), pick(2)]).ok()
    })
}

fn observations() -> impl Iterator<Item = [Observation; 3]> {
    (0..216usize).map(|n| {
        let pick = |digit: u32| KINDS[(n / 6usize.pow(digit)) % 6];
        [pick(0), pick(1), pick(2)]
    })
}

#[test]
fn copies_only_ever_land_on_writable_reachable_unrejected_durables() {
    for ladder in ladders() {
        for observed in observations() {
            for vault in [Vault::Sealed, Vault::Unsealed] {
                let Ok(open) = ladder.open(&observed, vault) else {
                    continue;
                };
                assert_eq!(observed[open.authority.index()], Holds(open.fingerprint));
                for target in open.copy_to.iter() {
                    let spec = ladder.spec(target).unwrap();
                    let seen = observed[target.index()];
                    assert_eq!(spec.access, Access::ReadWrite, "{observed:?}");
                    assert_ne!(seen, Unreachable, "{observed:?}");
                    assert_ne!(seen, Holds(open.fingerprint), "{observed:?}");
                    if spec.durability == Durability::Durable {
                        assert_eq!(seen, Empty, "{observed:?}");
                    }
                }
                let durable = observed.iter().zip(ladder.specs()).any(|(seen, spec)| {
                    *seen == Holds(open.fingerprint) && spec.durability == Durability::Durable
                });
                assert_eq!(open.custody == Custody::Durable, durable, "{observed:?}");
            }
        }
    }
}

#[test]
fn mint_never_fires_over_a_held_key_or_sealed_data() {
    for ladder in ladders() {
        for observed in observations() {
            assert_eq!(ladder.mint(&observed, Vault::Sealed), Err(Refusal::Sealed));
            let Ok(mint) = ladder.mint(&observed, Vault::Unsealed) else {
                continue;
            };
            assert!(
                !observed.iter().any(|seen| matches!(seen, Holds(_))),
                "{observed:?}"
            );
            assert_eq!(observed[mint.target.index()], Empty);
            assert_eq!(ladder.spec(mint.target), Some(SourceSpec::durable()));
        }
    }
}

#[test]
fn sealed_data_is_never_declared_lost_while_a_source_is_unreachable() {
    for ladder in ladders() {
        for observed in observations() {
            if ladder.open(&observed, Vault::Sealed) == Err(Refusal::Lost) {
                assert!(!observed.contains(&Unreachable), "{observed:?}");
            }
        }
    }
}
