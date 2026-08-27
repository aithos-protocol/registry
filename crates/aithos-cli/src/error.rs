//! One error type, because a command-line tool has exactly one way to fail:
//! print something a person can act on, and exit non-zero.

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

impl Error {
    pub fn msg(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

macro_rules! from {
    ($($t:ty),*) => { $(impl From<$t> for Error {
        fn from(e: $t) -> Self { Error(e.to_string()) }
    })* };
}
from!(
    std::io::Error,
    serde_json::Error,
    reqwest::Error,
    semver::Error
);

impl From<a2a_card::CardError> for Error {
    fn from(e: a2a_card::CardError) -> Self {
        // Every issue, each with the pointer to the member at fault. A person
        // fixing a card by hand needs the list, not the first line of it.
        let issues = e.issues();
        if issues.len() <= 1 {
            return Error(e.to_string());
        }
        let mut out = format!("the card was rejected, {} problems:", issues.len());
        for issue in issues {
            out.push_str(&format!("\n  {} {}", issue.pointer, issue.detail));
        }
        Error(out)
    }
}

impl From<registry_core::RegistryError> for Error {
    fn from(e: registry_core::RegistryError) -> Self {
        Error(e.to_string())
    }
}
