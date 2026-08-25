use thiserror::Error;

/// A machine-readable code, mirroring the problem codes of `SPEC.md` §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    JsonInvalid,
    CardInvalid,
    PresenceInvalid,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::JsonInvalid => "JSON_INVALID",
            Code::CardInvalid => "CARD_INVALID",
            Code::PresenceInvalid => "PRESENCE_INVALID",
        }
    }
}

/// One problem found at one location in the card.
///
/// `pointer` is an RFC 6901 JSON Pointer, so a client can highlight the exact
/// offending member rather than being told "the card is invalid".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub code: Code,
    pub pointer: String,
    pub detail: String,
}

impl Issue {
    pub(crate) fn new(code: Code, pointer: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code,
            pointer: pointer.into(),
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} at {}: {}",
            self.code.as_str(),
            if self.pointer.is_empty() {
                "/"
            } else {
                &self.pointer
            },
            self.detail
        )
    }
}

#[derive(Debug, Error)]
pub enum CardError {
    /// The bytes were not acceptable JSON under the strict profile of §5.1.
    #[error("{0}")]
    Json(Issue),
    /// The card parsed, but violates the pinned A2A schema or the presence rules.
    #[error("card rejected: {} issue(s), first: {first}", .issues.len(), first = .issues.first().map(|i| i.to_string()).unwrap_or_default())]
    Invalid { issues: Vec<Issue> },
    /// Canonicalization failed. Should be unreachable once §5.1 has passed.
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
}

impl CardError {
    pub fn issues(&self) -> Vec<Issue> {
        match self {
            CardError::Json(i) => vec![i.clone()],
            CardError::Invalid { issues } => issues.clone(),
            CardError::Canonicalization(d) => {
                vec![Issue::new(Code::JsonInvalid, "", d.clone())]
            }
        }
    }
}
