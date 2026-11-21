//! Key sources and the [`Custodian`] that executes the kernel's decisions.
//!
//! The kernel decides; this module reads and writes. Every source answers
//! with a [`Sighting`]: a key, a definite "no key here", or "could not ask".
//! A source that could not be asked is never mistaken for an empty one.

mod credentials_dir;
mod custodian;
mod error;
mod key_file;
#[cfg(feature = "keyring")]
mod keyring;
mod report;
pub mod testing;

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;

use zeroize::Zeroizing;

pub use credentials_dir::CredentialsDir;
pub use custodian::{Custodian, CustodyError, Key};
pub use error::SourceError;
pub use key_file::KeyFile;
#[cfg(feature = "keyring")]
pub use keyring::KeyringSource;
pub use report::{Report, Status};

use crate::SourceSpec;

/// Key bytes, wiped from memory when dropped.
pub type Secret = Zeroizing<Vec<u8>>;

/// The largest key a file-backed source reads: 64 KiB.
pub const MAX_KEY_BYTES: u64 = 64 * 1024;

/// What a source answered when asked for the key. `Debug` never shows the key.
pub enum Sighting {
    /// The source holds this key.
    Holds(Secret),
    /// The source answered, and it holds no key.
    Empty,
    /// The source could not be asked. It may hold a key nobody can see.
    Unreachable(SourceError),
}

impl std::fmt::Debug for Sighting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Holds(_) => f.write_str("Holds(<redacted>)"),
            Self::Empty => f.write_str("Empty"),
            Self::Unreachable(error) => f.debug_tuple("Unreachable").field(error).finish(),
        }
    }
}

/// Read a whole key file into one zeroizing buffer sized up front, so no
/// reallocation leaves key bytes behind.
pub(crate) fn read_key(mut file: File, path: &Path) -> Result<Secret, SourceError> {
    let shown = path.display();
    let len = file
        .metadata()
        .map_err(|error| SourceError::caused_by(format!("cannot inspect {shown}"), error))?
        .len();
    if len > MAX_KEY_BYTES {
        return Err(SourceError::new(format!(
            "{shown} is larger than {MAX_KEY_BYTES} bytes"
        )));
    }
    if len == 0 {
        return Err(SourceError::new(format!("{shown} is empty")));
    }
    let size = usize::try_from(len)
        .map_err(|_| SourceError::new(format!("{shown} does not fit in memory")))?;
    let changed = || SourceError::new(format!("{shown} changed while it was read"));
    let mut key = Zeroizing::new(vec![0; size]);
    file.read_exact(&mut key)
        .map_err(|error| match error.kind() {
            ErrorKind::UnexpectedEof => changed(),
            _ => SourceError::caused_by(format!("cannot read {shown}"), error),
        })?;
    let mut probe = Zeroizing::new([0_u8; 1]);
    let more = file
        .read(probe.as_mut_slice())
        .map_err(|error| SourceError::caused_by(format!("cannot read {shown}"), error))?;
    if more != 0 {
        return Err(changed());
    }
    Ok(key)
}

/// Whether `path` is definitely not there: the deepest entry on its way that
/// exists is a real directory, and nothing below it exists, dangling links
/// included. A path that cannot be resolved is not absent, it is unknown.
pub(crate) fn definitely_absent(path: &Path) -> bool {
    for ancestor in path.ancestors() {
        let probe = if ancestor.as_os_str().is_empty() {
            Path::new(".")
        } else {
            ancestor
        };
        match std::fs::symlink_metadata(probe) {
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return false,
            Ok(_) => {
                return ancestor != path && std::fs::metadata(probe).is_ok_and(|m| m.is_dir());
            }
        }
    }
    false
}

/// Somewhere a key can live.
pub trait Source: Send + Sync {
    /// A short name for reports: `"key file"`, `"macOS Keychain"`.
    fn name(&self) -> &str;
    /// Whether the source survives a reboot, and whether it may be written.
    fn spec(&self) -> SourceSpec;
    /// Ask the source for the key.
    fn read(&self) -> Sighting;
    /// Store `key`. The custodian only writes sources that answered empty or
    /// stale, reads every write back, and serializes nothing: callers hold
    /// their own lock.
    ///
    /// # Errors
    ///
    /// The source refused or failed the write.
    fn write(&self, key: &[u8]) -> Result<(), SourceError>;
}
