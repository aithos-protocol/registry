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
    DomainSyntaxInvalid,
    DomainIsPublicSuffix,
    DomainsNotCanonical,
    TooManyDomains,
    CertificationNotIncreasing,
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
            Code::DomainSyntaxInvalid => "DOMAIN_SYNTAX_INVALID",
            Code::DomainIsPublicSuffix => "DOMAIN_IS_PUBLIC_SUFFIX",
            Code::DomainsNotCanonical => "DOMAINS_NOT_CANONICAL",
            Code::TooManyDomains => "TOO_MANY_DOMAINS",
            Code::CertificationNotIncreasing => "CERTIFICATION_NOT_INCREASING",
        }
    }

    /// The HTTP status `SPEC.md` §9 pairs with this code.
    pub fn http_status(self) -> u16 {
        match self {
            Code::PrivateKeySubmitted => 400,
            Code::NotAuthorizedKey => 403,
            // `CERTIFICATION_NOT_INCREASING` sits with the other monotonicity
            // conflicts: the request is well formed and signed, it just lost a
            // race — or replayed a past — against the stored state.
            Code::AgentIdMismatch
            | Code::VersionNotIncreasing
            | Code::CertificationNotIncreasing => 409,
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
