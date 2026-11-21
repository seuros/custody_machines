use std::error::Error;
use std::fmt;

/// Why a source could not be read or written. Its message carries the cause.
#[derive(Debug)]
pub struct SourceError {
    context: String,
    cause: Option<Box<dyn Error + Send + Sync>>,
}

impl SourceError {
    /// An error with no underlying cause.
    #[must_use]
    pub fn new(context: impl Into<String>) -> Self {
        Self {
            context: context.into(),
            cause: None,
        }
    }

    /// An error caused by `cause`, which also appears in the message.
    #[must_use]
    pub fn caused_by(
        context: impl Into<String>,
        cause: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            context: context.into(),
            cause: Some(Box::new(cause)),
        }
    }
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.cause {
            Some(cause) => write!(f, "{}: {cause}", self.context),
            None => f.write_str(&self.context),
        }
    }
}

impl Error for SourceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause
            .as_deref()
            .map(|cause| cause as &(dyn Error + 'static))
    }
}
