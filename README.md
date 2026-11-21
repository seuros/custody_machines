# custody-machines

> A key that dies on reboot was never stored. 🔐

Key custody for Rust. You keep secrets in an encrypted file; the key that opens it has to live somewhere: a keychain, a key file, a systemd credential, the kernel keyring. Some of those survive a reboot and some do not, some answer and some are not running, and "found nothing" is not the same answer as "could not ask". This crate decides where the key comes from, where to copy it, when a fresh one may be minted, and when to refuse. No threads, no clock, no I/O in the core.

## Quick Start

```bash
cargo add custody-machines --features keyring
```

```rust
use custody_machines::{Custody, Ladder, Observation, Refusal, SourceSpec, Vault};

// Most preferred first: a keychain, a key file, the kernel keyring as a cache.
let ladder = Ladder::new([SourceSpec::durable(), SourceSpec::durable(), SourceSpec::cache()])?;
let k = [7; 32]; // the key's fingerprint, computed by you

// After a reboot the cache is empty, the keychain daemon is not running yet.
let seen = [Observation::Unreachable, Observation::Holds(k), Observation::Empty];
let open = ladder.open(&seen, Vault::Sealed)?;
assert_eq!(open.authority.index(), 1); // take it from the key file
assert_eq!(open.custody, Custody::Durable);
assert_eq!(open.copy_to.len(), 1); // and refill the cache

// Nothing found anywhere, but someone did not answer: that is not "lost".
let silent = [Observation::Unreachable, Observation::Empty, Observation::Empty];
assert_eq!(ladder.open(&silent, Vault::Sealed), Err(Refusal::Unavailable));
assert_eq!(ladder.mint(&silent, Vault::Sealed), Err(Refusal::Sealed)); // and never minted over
# Ok::<(), Box<dyn core::error::Error>>(())
```

The core is allocation-free `no_std` with no `unsafe`: you hand it what each source answered, it hands back a decision. The `stores` feature adds a key file, systemd credentials and the `Custodian` that reads, decides and copies; `keyring` adds the macOS Keychain, the Secret Service and the Linux kernel keyring. Local sources only: no password managers, no cloud. Rust only, no gem.

## A Message to the Resistance

So your CLI encrypts its credentials, and the key goes into the OS keyring, because that is what keyrings are for. On the Mac it works. On the Linux desktop it works. On the headless Linux box there is no Secret Service, so the keyring library quietly falls back to the kernel keyring, which takes the key and says thank you.

The kernel keyring lives in memory. It is gone at the next reboot, gone after three idle days, and unreachable from any shell whose login session has ended, which describes every tmux pane you started over SSH last week. Your encrypted file is still on disk. Its key is not. The next run reports "credential vault unlock key is missing; restore it from backup", and nobody has a backup, because nobody knew there was something to back up.

You add a fallback: if the keyring fails, use a file. It never fires. The keyring did not fail. It answered "no such key", which is the honest answer from a store that forgot, and your code reads it as "first run" and mints a fresh key over the old vault.

What you wanted was a small, boring piece of bookkeeping. Rank the places a key can live. Know which of them survive a reboot. Never let the only copy sit in one that does not. Treat "could not ask" as its own answer. Mint only when nothing is sealed. When two places disagree, ask which key opens the vault instead of guessing. That is this crate.

## Chapter 1: Stardate 2026.325, the AMS Kerckhoffs

> **AMS Kerckhoffs**, NCC-4239, *Kerckhoffs*-class custody tender.
> The tender keeps the fleet's keys. It assumes the enemy has read every manual aboard.

Auguste Kerckhoffs wrote in 1883 that a cipher must stay secure when everything about it is known except the key. The tender takes the corollary seriously: everything rests on the key, so the key is the one thing that may never be mislaid. It keeps a copy in the captain's safe, one in the purser's strongbox, and one chalked on the wardroom slate for convenience, and it knows the slate is wiped at every change of watch.

On a bridge somewhere, a cadet volunteers:

```rust,ignore
fn vault_key(keyring: &Keyring) -> Key {
    keyring.get().unwrap_or_else(|| {
        let key = Key::generate(); // first run, probably
        keyring.set(&key);
        key
    })
}
```

The slate was wiped at the change of watch. The safe's officer is ashore. The strongbox holds the key the whole time.

"That," says the tender's quartermaster, "is changing the locks because the slate by the door is blank, and sealing tomorrow's orders with a key written in chalk."

## The Flight Plan

1. **Describe the ladder once.** Each source is `durable()` (survives a reboot), `provisioned()` (durable, written by someone else, such as systemd) or `cache()` (gone at reboot). At least one must be durable, or `Ladder::new` refuses.
2. **Observe every source.** `Holds(fingerprint)`, `Empty`, `Unreachable`, or `Rejected(fingerprint)` for a key you proved does not open the vault.
3. **Ask.** `open` names the authority and the sources to copy into. `mint` names where a fresh key goes. `Open::permit_write` says whether data may be sealed under the key.
4. **Or let the `Custodian` do all three** with real sources:

```rust
# #[cfg(feature = "stores")]
# {
use custody_machines::Vault;
use custody_machines::stores::testing::MemorySource;
use custody_machines::stores::{Custodian, Secret};

let file = MemorySource::durable("key file");
let cache = MemorySource::cache("kernel keyring");
let custodian = Custodian::new("my-app/vault-key/v1", [
    Box::new(file.clone()) as Box<dyn custody_machines::stores::Source>,
    Box::new(cache.clone()),
])?;

let opens = |_: &[u8]| true; // over sealed data: asked on disagreement or a silent source
let fresh = || Secret::new(b"a key from your CSPRNG".to_vec());
let key = custodian.open_or_mint(Vault::Unsealed, opens, fresh)?;
key.permit_write()?;

cache.wipe(); // reboot
let again = custodian.open(Vault::Sealed, opens)?;
assert_eq!(again.secret(), key.secret());
assert!(cache.holds(key.secret())); // refilled
# }
# Ok::<(), Box<dyn std::error::Error>>(())
```

## How the Tender Works

### Sources

A ladder lists where a key may live, most preferred first. Each source is one of three kinds:

| `SourceSpec` | Means |
| --- | --- |
| `durable()` | Survives a reboot, and the custodian may write it: a keychain, a key file. |
| `provisioned()` | Survives a reboot, written by someone else: a systemd credential. Never written. |
| `cache()` | Gone after a reboot or an idle expiry: the Linux kernel keyring. Never the only copy. |

Every source answers each time with one of four observations: `Holds(fingerprint)`, `Empty`, `Unreachable`, or `Rejected(fingerprint)` for a key you proved does not open the vault.

### Durable beats volatile

The authority is the most preferred durable source holding the key. A cache is only a cache: when it disagrees over unsealed data it is refreshed, and over sealed data the disagreement is settled by asking which key opens the vault. Durable holders rank before caches in that question, so a cache never outvotes a keychain.

### Copies go only where they are safe

Writable caches that are empty, stale or rejected get the key. So does the most preferred writable durable source that answered empty and ranks above the best durable holder. That one rule rescues a cache-only key into durable storage and moves a key up when a better source appears. Read-only, unreachable and rejected durable sources are never written, and every write is read back before it counts.

### `Unreachable` is not `Empty`

Sealed data with no visible key is `Lost` only when every source answered. If one stayed silent it is `Unavailable`: retry, do not mint. While a source is silent, the visible key over sealed data is proven with `opens` before use, because the silent one may hold the key that really sealed it.

### Minting

`mint` refuses `Sealed` data and `Occupied` sources, and wants a reachable writable durable target or refuses `NoDurableSink`. The `Custodian` checks the fresh key's size, stores it there first, reads it back, and only then fills caches.

With no sealed data, `mint` does not wait for a silent source: a host with no Secret Service could otherwise never mint. If that source comes back holding an old key, the next `open` over the sealed vault sees the divergence and keeps the key that opens it. The old copy is `Rejected` and left alone.

### Writing data

`permit_write` refuses `VolatileOnly`, so a vault is never sealed under a key that dies on reboot.

### Errors say why

Every refusal from the `Custodian` carries a report of what each source answered, causes included:

```text
the vault is sealed, no reachable source holds its key, and one is silent
[Secret Service: unreachable (cannot connect Secret Service: ...); key file: empty;
 kernel keyring: unreachable (... Couldn't access platform storage: KeyRevoked)]
```

## The Rules of the Tender

- The core reads no clock, does no I/O and keeps no state: every answer is a function of the ladder, the observations and whether data is sealed. A refusal changes nothing because there is nothing to change.
- One exhaustive `Refusal`. No `#[non_exhaustive]`, no panics at run time.
- Fingerprints are yours: the core only compares them. The `Custodian` uses SHA-256 over your domain string and the key.
- The `Custodian` takes no lock, and both `open` and `open_or_mint` write. If another process shares the sources, hold your own lock around every call. Every write is read back before it counts, and the key file never replaces an existing file, so a lost race fails loudly instead of overwriting.
- The key file is private by mode bits and ownership, as OpenSSH's `StrictModes`: `0700` directories, a `0600` file owned by the effective user, in a directory no one else may write. Names containing `.custody-tmp.` next to a key file are reserved for its temporary copies. ACLs are not inspected; on macOS use the Keychain.
- `Debug` never prints key bytes: `Sighting`, `Key` and `MemorySource` redact them, and file reads land in one pre-sized zeroizing buffer.
- Keyring adapters own their store: no process-global default store, and a store that failed to connect is retried on the next read.

## What You Think You're Doing vs Reality

### You Think: "The keyring returned no key, so this is the first run."
### Reality: The kernel keyring forgot it at the last reboot.

Minting now orphans every byte sealed under the old key. The answer "no such key" is honest from a store that forgets; reading it as "first run" is the bug.

### You Think: "The keyring call succeeded, so the key is stored."
### Reality: It is stored until the next reboot, or three idle days.

The kernel keyring takes the key and says thank you. It never says for how long. `permit_write` asks the question the call did not.

### You Think: "No Secret Service means no key there."
### Reality: No Secret Service means you could not ask.

A daemon that has not started yet, a session bus that is gone, a session keyring revoked when the SSH login that started your tmux ended: all of them are `Unreachable`, and none of them is evidence of absence.

### You Think: "A key file is less secure than a keyring."
### Reality: Against your own user, neither protects anything.

Root and your own processes can read both. Against a reboot, only one of them survives. The key file is checked like OpenSSH checks `~/.ssh`, and on a headless host it is the honest answer.

## What's Yours

This is a pre-1.0 core; breaking changes land in minor versions. It is not a secrets manager and it talks to no password manager or cloud service: local sources only. You own the key generator (`generate`, from a CSPRNG), the decision whether data is sealed, the proof of which key opens it (`opens`), the lock that keeps two processes from minting at once, and the ladder itself. A sensible Linux ladder is `CredentialsDir`, `secret_service`, `KeyFile`, `keyutils`; a sensible macOS one is `CredentialsDir`, `keychain`.

## License

MIT. See [LICENSE.txt](LICENSE.txt).
