use std::ffi::OsStr;
use std::fs::File;
use std::io::ErrorKind;
use std::path::PathBuf;

use super::{Sighting, Source, SourceError, definitely_absent, read_key};
use crate::SourceSpec;

/// A key systemd hands the service: `LoadCredential=` or
/// `LoadCredentialEncrypted=`, read from `$CREDENTIALS_DIRECTORY`.
///
/// Durable and read-only: someone else provisions it. With no credentials
/// directory, or no credential of that name, it answers empty.
#[derive(Debug, Clone)]
pub struct CredentialsDir {
    dir: Option<PathBuf>,
    name: String,
}

impl CredentialsDir {
    /// The credential `name` in this process's `$CREDENTIALS_DIRECTORY`.
    #[must_use]
    pub fn from_env(name: impl Into<String>) -> Self {
        let dir = std::env::var_os("CREDENTIALS_DIRECTORY")
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from);
        Self {
            dir,
            name: name.into(),
        }
    }

    /// The credential `name` in `dir`.
    #[must_use]
    pub fn at(dir: impl Into<PathBuf>, name: impl Into<String>) -> Self {
        Self {
            dir: Some(dir.into()),
            name: name.into(),
        }
    }
}

impl Source for CredentialsDir {
    fn name(&self) -> &'static str {
        "systemd credential"
    }

    fn spec(&self) -> SourceSpec {
        SourceSpec::provisioned()
    }

    fn read(&self) -> Sighting {
        let Some(dir) = &self.dir else {
            return Sighting::Empty;
        };
        if self.name.is_empty() || self.name.contains('/') || OsStr::new(&self.name) == ".." {
            return Sighting::Unreachable(SourceError::new(format!(
                "invalid credential name {:?}",
                self.name
            )));
        }
        let path = dir.join(&self.name);
        match File::open(&path) {
            Ok(file) => match read_key(file, &path) {
                Ok(key) => Sighting::Holds(key),
                Err(error) => Sighting::Unreachable(error),
            },
            Err(error) if error.kind() == ErrorKind::NotFound && definitely_absent(&path) => {
                Sighting::Empty
            }
            Err(error) => Sighting::Unreachable(SourceError::caused_by(
                format!("cannot open {}", path.display()),
                error,
            )),
        }
    }

    fn write(&self, _key: &[u8]) -> Result<(), SourceError> {
        Err(SourceError::new(
            "a systemd credential is provisioned by systemd, not written",
        ))
    }
}

#[cfg(test)]
mod tests;
