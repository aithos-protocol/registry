//! RFC 9457 `application/problem+json` responses.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use registry_core::Code as CoreCode;

/// A problem, carrying the machine-readable code of `SPEC.md` §9.
#[derive(Debug, Clone)]
pub struct Problem {
    pub status: StatusCode,
    pub code: &'static str,
    pub detail: String,
    /// RFC 6901 pointer into the request body, when one applies.
    pub pointer: Option<String>,
}

impl Problem {
    pub fn new(status: u16, code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            code,
            detail: detail.into(),
            pointer: None,
        }
    }

    pub fn at(mut self, pointer: impl Into<String>) -> Self {
        self.pointer = Some(pointer.into());
        self
    }

    pub fn json_invalid(detail: impl Into<String>) -> Self {
        Self::new(400, "JSON_INVALID", detail)
    }

    pub fn not_found() -> Self {
        Self::new(404, "NOT_FOUND", "no such agent in this registry")
    }

    fn title(&self) -> &'static str {
        match self.code {
            "JSON_INVALID" => "Invalid JSON",
            "PRIVATE_KEY_SUBMITTED" => "Private key material submitted",
            "NOT_AUTHORIZED_KEY" => "Not signed by an authorized key",
            "NOT_FOUND" => "Not found",
            "AGENT_ID_MISMATCH" => "Identifier does not match the signing key",
            "VERSION_NOT_INCREASING" => "Card version does not move forward",
            "WITHDRAWN" => "Entry was withdrawn",
            "PRECONDITION_FAILED" => "Precondition failed",
            "CARD_TOO_LARGE" => "Agent Card is too large",
            "CARD_INVALID" => "Agent Card is invalid",
            "PRESENCE_INVALID" => "Field presence rules were not applied",
            "SIGNATURE_INVALID" => "Signature is invalid",
            "KID_NOT_THUMBPRINT" => "Key identifier is not the key's thumbprint",
            "ALG_NOT_ALLOWED" => "Algorithm is not allowed",
            "UNUSED_KEY" => "A submitted key signs nothing",
            "TOO_MANY_KEYS" => "Too many keys submitted",
            "DUPLICATE_KEY" => "The same key was submitted twice",
            "KEY_INVALID" => "A submitted key is malformed",
            "UNPROVEN_KEY" => "A signing key did not ask for this publication",
            // Codes produced by the layers around the handlers, which had no
            // arm here and so all read "Request rejected" — the one field of a
            // problem document a human sees first, saying nothing.
            "METHOD_NOT_ALLOWED" => "Method not allowed",
            "RATE_LIMITED" => "Too many requests",
            "FORBIDDEN" => "Not reachable this way",
            "INTERNAL" => "The registry could not complete this request",
            "REQUEST_REFUSED" => "Request refused",
            "CONFLICT" => "The agent changed concurrently",
            "CURSOR_INVALID" => "Pagination cursor is not valid",
            _ => "Request rejected",
        }
    }

    /// The kebab-case slug used in the problem `type` URI.
    fn slug(&self) -> String {
        self.code.to_ascii_lowercase().replace('_', "-")
    }
}

impl From<registry_core::RegistryError> for Problem {
    fn from(e: registry_core::RegistryError) -> Self {
        Problem::new(e.code.http_status(), code_str(e.code), e.detail)
    }
}

fn code_str(code: CoreCode) -> &'static str {
    // `Code::as_str` already returns a &'static str; this keeps the type.
    code.as_str()
}

impl From<a2a_card::CardError> for Problem {
    fn from(e: a2a_card::CardError) -> Self {
        let issues = e.issues();
        let Some(first) = issues.first() else {
            return Problem::json_invalid("card rejected");
        };
        let status = match first.code {
            a2a_card::Code::JsonInvalid => 400,
            _ => 422,
        };
        let mut p = Problem::new(status, first.code.as_str(), first.detail.clone());
        if !first.pointer.is_empty() {
            p = p.at(first.pointer.clone());
        }
        p
    }
}

impl From<crate::store::StoreError> for Problem {
    fn from(e: crate::store::StoreError) -> Self {
        match e {
            crate::store::StoreError::Conflict => Problem::new(
                409,
                "CONFLICT",
                "the agent was modified while this request was being processed; re-read and retry",
            ),
            crate::store::StoreError::BadCursor => Problem::new(
                400,
                "CURSOR_INVALID",
                "the `cursor` parameter did not come from this registry",
            )
            .at("/cursor"),
            // The detail names tables, indexes and request ids. It belongs in
            // the log, where an operator can correlate it, not in a public
            // response describing the inside of the service to anyone who
            // provokes an error.
            crate::store::StoreError::Backend(detail) => {
                tracing::error!(%detail, "storage backend failure");
                Problem::new(
                    500,
                    "INTERNAL",
                    "the registry could not complete this request",
                )
            }
        }
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let mut body = json!({
            "type": format!("/problems/{}", self.slug()),
            "title": self.title(),
            "status": self.status.as_u16(),
            "code": self.code,
            "detail": self.detail,
        });
        if let Some(pointer) = &self.pointer {
            body["pointer"] = json!(pointer);
        }
        (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            serde_json::to_string(&body).unwrap_or_default(),
        )
            .into_response()
    }
}
