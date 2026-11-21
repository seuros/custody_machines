/// A digest of a key, computed by the caller. The kernel only compares them.
pub type Fingerprint = [u8; 32];

/// Whether a source still holds its key after the host reboots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Durability {
    /// Survives a reboot: a keychain, a key file, a systemd credential.
    Durable,
    /// Gone after a reboot or an idle expiry: the Linux kernel keyring.
    Volatile,
}

/// Whether the custodian may write a key into a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Access {
    /// The custodian may store and refresh the key here.
    ReadWrite,
    /// Provisioned by someone else, read only: a systemd credential.
    ReadOnly,
}

/// What a source is, fixed when the ladder is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceSpec {
    /// Whether the source survives a reboot.
    pub durability: Durability,
    /// Whether the custodian may write to it.
    pub access: Access,
}

impl SourceSpec {
    /// A durable source the custodian may write.
    #[must_use]
    pub const fn durable() -> Self {
        Self {
            durability: Durability::Durable,
            access: Access::ReadWrite,
        }
    }

    /// A durable source provisioned by someone else.
    #[must_use]
    pub const fn provisioned() -> Self {
        Self {
            durability: Durability::Durable,
            access: Access::ReadOnly,
        }
    }

    /// A cache that is gone after a reboot.
    #[must_use]
    pub const fn cache() -> Self {
        Self {
            durability: Durability::Volatile,
            access: Access::ReadWrite,
        }
    }

    pub(crate) const fn is_durable(self) -> bool {
        matches!(self.durability, Durability::Durable)
    }

    pub(crate) const fn is_writable(self) -> bool {
        matches!(self.access, Access::ReadWrite)
    }
}

/// What the caller saw in one source, just now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Observation {
    /// The source answered with a key.
    Holds(Fingerprint),
    /// The source answered, and it holds no key.
    Empty,
    /// The source did not answer: no provider, a revoked session, no permission.
    /// It may hold a key nobody can see right now.
    Unreachable,
    /// The source holds a key the caller proved does not open the vault.
    Rejected(Fingerprint),
}

/// Whether encrypted data already depends on a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Vault {
    /// Data is sealed under some key: losing it loses the data.
    Sealed,
    /// Nothing is sealed yet: a key may be minted.
    Unsealed,
}

/// A source's position in its ladder, most preferred first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceId(u8);

impl SourceId {
    pub(crate) const fn new(index: u8) -> Self {
        Self(index)
    }

    /// The position in the ladder, and in the caller's array of sources.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// A set of sources in one ladder.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct SourceSet(u16);

impl SourceSet {
    /// No source.
    pub const EMPTY: Self = Self(0);

    pub(crate) const fn with(self, id: SourceId) -> Self {
        Self(self.0 | (1 << id.0))
    }

    /// Whether `id` is in the set.
    #[must_use]
    pub const fn contains(self, id: SourceId) -> bool {
        id.0 < 16 && self.0 & (1 << id.0) != 0
    }

    /// Whether the set has no source.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// How many sources are in the set.
    #[must_use]
    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// The sources in ladder order.
    pub fn iter(self) -> impl Iterator<Item = SourceId> {
        (0..16u8).map(SourceId).filter(move |id| self.contains(*id))
    }
}
