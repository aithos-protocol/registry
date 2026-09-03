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
    /// Per-domain outcomes, for the two DNS problems of
    /// `DOMAIN-CERTIFICATION.md` §11. RFC 9457 extension member: without it a
    /// request naming four domains would have to be bisected to find which one
    /// failed.
    pub domains: Option<serde_json::Value>,
}

impl Problem {
    pub fn new(status: u16, code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            code,
            detail: detail.into(),
            pointer: None,
            domains: None,
        }
    }

    pub fn at(mut self, pointer: impl Into<String>) -> Self {
        self.pointer = Some(pointer.into());
        self
    }

    pub fn with_domains(mut self, outcomes: serde_json::Value) -> Self {
        self.domains = Some(outcomes);
        self
    }

    pub fn json_invalid(detail: impl Into<String>) -> Self {
        Self::new(400, "JSON_INVALID", detail)
    }

    pub fn not_found() -> Self {
        Self::new(404, "NOT_FOUND", "no such agent in this registry")
    }

    /// The `title` member, from the catalogue.
    ///
    /// This was a `match` repeating every code, which is how the codes the
    /// layers around the handlers produce ended up with no arm and all read
    /// "Request rejected" — the one field of a problem document a human sees
    /// first, saying nothing. One list, checked against the specification by
    /// `tests/openapi.rs`, cannot drift that way again.
    fn title(&self) -> &'static str {
        crate::catalog::lookup(self.code).map_or("Request rejected", |d| d.title)
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
        if let Some(domains) = &self.domains {
            body["domains"] = domains.clone();
        }
        (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            serde_json::to_string(&body).unwrap_or_default(),
        )
            .into_response()
    }
}
