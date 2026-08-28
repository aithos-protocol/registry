use thiserror::Error;

/// Problem codes of `SPEC.md` §9 that this crate can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    PrivateKeySubmitted,
    NotAuthorizedKey,
    AgentIdMismatch,
    VersionNotIncreasing,
    Withdrawn,
    SignatureInvalid,
    KidNotThumbprint,
    AlgNotAllowed,
    UnusedKey,
    TooManyKeys,
    DuplicateKey,
    KeyInvalid,
    UnprovenKey,
    CardInvalid,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::PrivateKeySubmitted => "PRIVATE_KEY_SUBMITTED",
            Code::NotAuthorizedKey => "NOT_AUTHORIZED_KEY",
            Code::AgentIdMismatch => "AGENT_ID_MISMATCH",
            Code::VersionNotIncreasing => "VERSION_NOT_INCREASING",
            Code::Withdrawn => "WITHDRAWN",
            Code::SignatureInvalid => "SIGNATURE_INVALID",
            Code::KidNotThumbprint => "KID_NOT_THUMBPRINT",
            Code::AlgNotAllowed => "ALG_NOT_ALLOWED",
            Code::UnusedKey => "UNUSED_KEY",
            Code::TooManyKeys => "TOO_MANY_KEYS",
            Code::DuplicateKey => "DUPLICATE_KEY",
            Code::KeyInvalid => "KEY_INVALID",
            Code::UnprovenKey => "UNPROVEN_KEY",
            Code::CardInvalid => "CARD_INVALID",
        }
    }

    /// The HTTP status `SPEC.md` §9 pairs with this code.
    pub fn http_status(self) -> u16 {
        match self {
            Code::PrivateKeySubmitted => 400,
            Code::NotAuthorizedKey => 403,
            Code::AgentIdMismatch | Code::VersionNotIncreasing => 409,
            Code::Withdrawn => 410,
            _ => 422,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{}: {detail}", code.as_str())]
pub struct RegistryError {
    pub code: Code,
    pub detail: String,
}

impl RegistryError {
    pub fn new(code: Code, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, RegistryError>;
