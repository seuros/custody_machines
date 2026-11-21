use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::process::geteuid;

use super::{Secret, Sighting, Source, SourceError, definitely_absent, read_key};
use crate::SourceSpec;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A key in a file only its owner can read. Durable and writable.
///
/// Missing directories are created `0700` and the file `0600`. Every read
/// and write syncs the whole directory chain, so the key never counts as
/// durable while an entry on its path may still be lost. A file readable by
/// group or others, owned by another user, or kept in a directory others
/// may write to is refused, not used. Names containing `.custody-tmp.` are
/// reserved for its temporary copies. Writes never replace an existing
/// file: a concurrent writer's key wins and this write fails.
#[derive(Debug, Clone)]
pub struct KeyFile {
    path: PathBuf,
}

impl KeyFile {
    /// A key file at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Where the key lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_key(&self) -> Result<Option<Secret>, SourceError> {
        self.check_name()?;
        self.sweep_temps();
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                if definitely_absent(&self.path) {
                    return Ok(None);
                }
                return Err(self.failed("cannot resolve", error));
            }
            Err(error) => return Err(self.failed("cannot open", error)),
        };
        let metadata = file
            .metadata()
            .map_err(|error| self.failed("cannot inspect", error))?;
        if !metadata.is_file() {
            return Err(SourceError::new(format!(
                "{} is not a file",
                self.path.display()
            )));
        }
        if metadata.mode() & 0o077 != 0 {
            return Err(SourceError::new(format!(
                "{} is readable by group or others; chmod 600 it",
                self.path.display()
            )));
        }
        let euid = geteuid().as_raw();
        if metadata.uid() != euid {
            return Err(SourceError::new(format!(
                "{} is owned by uid {}, not by this process's uid {euid}",
                self.path.display(),
                metadata.uid()
            )));
        }
        path::trust(&self.path).map_err(SourceError::new)?;
        path::tolerate_read_only(file.sync_all())
            .map_err(|error| self.failed("cannot sync the contents of", error))?;
        let key = read_key(file, &self.path)?;
        path::sync_chain(&self.path).map_err(|error| self.failed("cannot make durable", error))?;
        Ok(Some(key))
    }

    fn dir(&self) -> &Path {
        self.path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }

    fn write_key(&self, key: &[u8]) -> Result<(), SourceError> {
        self.check_name()?;
        let dir = self.dir();
        path::create_dirs(dir)
            .map_err(|error| self.failed("cannot create the directory for", error))?;
        path::trust(dir).map_err(SourceError::new)?;
        self.sweep_temps();
        let name = self.temp_prefix();
        let unique = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp = dir.join(format!("{name}{}.{unique}", std::process::id()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|error| self.failed("cannot create a temporary file for", error))?;
        let published = fill(file, key).and_then(|()| fs::hard_link(&temp, &self.path));
        if let Err(error) = published {
            let _ = fs::remove_file(&temp);
            return Err(self.failed("cannot write", error));
        }
        if let Err(error) = path::sync_chain(&self.path) {
            let _ = fs::remove_file(&temp);
            let withdrawn = fs::remove_file(&self.path).and_then(|()| path::sync_dir(dir));
            let what = match withdrawn {
                Ok(()) => "cannot sync the directory of",
                Err(_) => "cannot sync, and cannot withdraw, the unsynced",
            };
            return Err(self.failed(what, error));
        }
        fs::remove_file(&temp)
            .and_then(|()| path::sync_dir(dir))
            .map_err(|error| self.failed("stored, but cannot remove the temporary copy of", error))
    }

    /// Names containing `.custody-tmp.` are reserved for this crate's
    /// temporary copies, so one key file can never sweep another.
    fn check_name(&self) -> Result<(), SourceError> {
        let reserved = self
            .path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().contains(".custody-tmp."));
        if reserved {
            return Err(SourceError::new(format!(
                "{} uses the reserved `.custody-tmp.` name",
                self.path.display()
            )));
        }
        Ok(())
    }

    fn temp_prefix(&self) -> String {
        let name = self
            .path
            .file_name()
            .map_or_else(|| "key".into(), |n| n.to_string_lossy());
        format!(".{name}.custody-tmp.")
    }

    /// Remove temporary copies a crashed write left behind, only in this
    /// crate's own `.<name>.custody-tmp.<pid>.<n>` names, so no stray copy of the
    /// key outlives the published one. Callers hold their lock, so no live
    /// write is in flight. Best effort: a copy that cannot be removed is no
    /// reason to refuse the key itself.
    fn sweep_temps(&self) {
        let prefix = self.temp_prefix();
        let Ok(entries) = fs::read_dir(self.dir()) else {
            return;
        };
        let mut removed = false;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let owned = name
                .to_string_lossy()
                .strip_prefix(&prefix)
                .is_some_and(|rest| {
                    rest.split_once('.').is_some_and(|(pid, n)| {
                        pid.parse::<u32>().is_ok() && n.parse::<u64>().is_ok()
                    })
                });
            if owned {
                removed |= fs::remove_file(entry.path()).is_ok();
            }
        }
        if removed {
            let _ = path::sync_dir(self.dir());
        }
    }

    fn failed(&self, what: &str, error: std::io::Error) -> SourceError {
        SourceError::caused_by(format!("{what} {}", self.path.display()), error)
    }
}

impl Source for KeyFile {
    fn name(&self) -> &'static str {
        "key file"
    }

    fn spec(&self) -> SourceSpec {
        SourceSpec::durable()
    }

    fn read(&self) -> Sighting {
        match self.read_key() {
            Ok(Some(key)) => Sighting::Holds(key),
            Ok(None) => Sighting::Empty,
            Err(error) => Sighting::Unreachable(error),
        }
    }

    fn write(&self, key: &[u8]) -> Result<(), SourceError> {
        self.write_key(key)
    }
}

fn fill(mut file: File, key: &[u8]) -> std::io::Result<()> {
    file.write_all(key)?;
    file.sync_all()
}

mod path;

#[cfg(test)]
mod tests;
