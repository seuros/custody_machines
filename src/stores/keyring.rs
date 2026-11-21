use std::sync::{Arc, Mutex, PoisonError};

use keyring_core::{CredentialStore, Entry, Error as KeyringError};
use zeroize::Zeroizing;

use super::{Sighting, Source, SourceError};
use crate::SourceSpec;

type Connect = fn() -> keyring_core::Result<Arc<CredentialStore>>;

/// A key in an OS keyring, addressed by service and account.
///
/// The store is connected on first use and again after a failure, so a
/// keyring that starts after this process is picked up. No process-global
/// default store is touched.
pub struct KeyringSource {
    name: &'static str,
    spec: SourceSpec,
    service: String,
    account: String,
    connect: Connect,
    store: Mutex<Option<Arc<CredentialStore>>>,
}

impl KeyringSource {
    /// The macOS login Keychain. Durable.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn keychain(service: impl Into<String>, account: impl Into<String>) -> Self {
        fn connect() -> keyring_core::Result<Arc<CredentialStore>> {
            Ok(apple_native_keyring_store::keychain::Store::new()?)
        }
        Self::new(
            "macOS Keychain",
            SourceSpec::durable(),
            service,
            account,
            connect,
        )
    }

    /// The freedesktop Secret Service: GNOME Keyring, `KWallet`, `KeePassXC`.
    /// Durable. Unreachable unless a provider answers on the session bus.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    #[must_use]
    pub fn secret_service(service: impl Into<String>, account: impl Into<String>) -> Self {
        fn connect() -> keyring_core::Result<Arc<CredentialStore>> {
            Ok(dbus_secret_service_keyring_store::Store::new()?)
        }
        Self::new(
            "Secret Service",
            SourceSpec::durable(),
            service,
            account,
            connect,
        )
    }

    /// The Linux kernel keyring. Volatile: gone after a reboot or three idle
    /// days, and unreachable when the session keyring was revoked.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn keyutils(service: impl Into<String>, account: impl Into<String>) -> Self {
        fn connect() -> keyring_core::Result<Arc<CredentialStore>> {
            Ok(linux_keyutils_keyring_store::Store::new()?)
        }
        Self::new(
            "kernel keyring",
            SourceSpec::cache(),
            service,
            account,
            connect,
        )
    }

    fn new(
        name: &'static str,
        spec: SourceSpec,
        service: impl Into<String>,
        account: impl Into<String>,
        connect: Connect,
    ) -> Self {
        Self {
            name,
            spec,
            service: service.into(),
            account: account.into(),
            connect,
            store: Mutex::new(None),
        }
    }

    fn entry(&self) -> Result<Entry, SourceError> {
        let store = {
            let mut slot = self.store.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(store) = slot.as_ref() {
                Arc::clone(store)
            } else {
                let store =
                    (self.connect)().map_err(|error| self.failed("cannot connect", error))?;
                *slot = Some(Arc::clone(&store));
                store
            }
        };
        store
            .build(&self.service, &self.account, None)
            .map_err(|error| self.failed("cannot address the entry in", error))
    }

    fn forget_store(&self) {
        *self.store.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    fn failed(&self, what: &str, error: KeyringError) -> SourceError {
        SourceError::caused_by(format!("{what} {}", self.name), error)
    }
}

impl Source for KeyringSource {
    fn name(&self) -> &str {
        self.name
    }

    fn spec(&self) -> SourceSpec {
        self.spec
    }

    fn read(&self) -> Sighting {
        let entry = match self.entry() {
            Ok(entry) => entry,
            Err(error) => return Sighting::Unreachable(error),
        };
        match entry.get_secret() {
            Ok(key) if key.is_empty() => Sighting::Unreachable(SourceError::new(format!(
                "{} holds an empty key",
                self.name
            ))),
            Ok(key) => Sighting::Holds(Zeroizing::new(key)),
            Err(KeyringError::NoEntry) => Sighting::Empty,
            Err(error) => {
                self.forget_store();
                Sighting::Unreachable(self.failed("cannot read", error))
            }
        }
    }

    fn write(&self, key: &[u8]) -> Result<(), SourceError> {
        self.entry()?.set_secret(key).map_err(|error| {
            self.forget_store();
            self.failed("cannot write", error)
        })
    }
}

impl std::fmt::Debug for KeyringSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyringSource")
            .field("name", &self.name)
            .field("service", &self.service)
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
