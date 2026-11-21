use std::fmt;

/// What one source answered, and what the custodian did with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// It holds the key in use.
    Holds,
    /// It answered with no key.
    Empty,
    /// It could not be asked; the message says why.
    Unreachable(String),
    /// It holds a key that does not open the vault. Left untouched.
    Rejected,
    /// It holds a different key that also opens the vault; the higher-ranked
    /// one is used. A durable source is left untouched; a cache is refreshed
    /// with the key in use, as caches always are.
    Alternate,
    /// The key was copied into it.
    Copied,
    /// Copying the key into it failed; the message says why.
    CopyFailed(String),
}

/// Every source by name, with its [`Status`], in ladder order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    entries: Vec<(String, Status)>,
}

impl Report {
    pub(crate) const fn new(entries: Vec<(String, Status)>) -> Self {
        Self { entries }
    }

    /// Every source by name, with its status, in ladder order.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &Status)> {
        self.entries
            .iter()
            .map(|(name, status)| (name.as_str(), status))
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Holds => f.write_str("holds the key"),
            Self::Empty => f.write_str("empty"),
            Self::Unreachable(why) => write!(f, "unreachable ({why})"),
            Self::Rejected => f.write_str("holds a key that does not open the vault"),
            Self::Alternate => f.write_str("holds another key that also opens the vault"),
            Self::Copied => f.write_str("key copied in"),
            Self::CopyFailed(why) => write!(f, "copy failed ({why})"),
        }
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, (name, status)) in self.entries.iter().enumerate() {
            if index > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{name}: {status}")?;
        }
        Ok(())
    }
}
