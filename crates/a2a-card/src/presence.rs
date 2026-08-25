//! Schema and field-presence validation, per `SPEC.md` §5.2 and A2A §8.4.1.
//!
//! The registry validates that a submitted card already satisfies the presence
//! rules; it never rewrites the card. Rewriting would change bytes the client
//! has already signed.

use serde_json::Value;

use crate::error::{Code, Issue};
use crate::schema::{AGENT_CARD, Behavior, Field, Msg, Ty};

/// Validate a value against the pinned `AgentCard` schema.
///
/// Returns every issue found, not just the first, so a publishing UI can show
/// a complete list.
pub fn validate_card(v: &Value) -> Vec<Issue> {
    let mut issues = Vec::new();
    validate_msg(v, &AGENT_CARD, "", &mut issues);
    issues
}

fn validate_msg(v: &Value, msg: &Msg, ptr: &str, issues: &mut Vec<Issue>) {
    let Some(obj) = v.as_object() else {
        issues.push(Issue::new(
            Code::CardInvalid,
            ptr,
            format!("expected an object for {}", msg.name),
        ));
        return;
    };

    for key in obj.keys() {
        if !msg.fields.iter().any(|f| f.name == *key) {
            issues.push(Issue::new(
                Code::CardInvalid,
                child(ptr, key),
                format!("member is unknown to {} in the pinned A2A schema", msg.name),
            ));
        }
    }

    if msg.is_oneof {
        let set: Vec<&str> = msg
            .fields
            .iter()
            .filter(|f| obj.contains_key(f.name))
            .map(|f| f.name)
            .collect();
        if set.len() > 1 {
            issues.push(Issue::new(
                Code::CardInvalid,
                ptr,
                format!("{} is a oneof; members {set:?} are all present", msg.name),
            ));
        }
    }

    for field in msg.fields {
        let p = child(ptr, field.name);
        match obj.get(field.name) {
            None => {
                if field.behavior == Behavior::Required {
                    issues.push(Issue::new(
                        Code::CardInvalid,
                        p,
                        "required member is absent".to_string(),
                    ));
                }
            }
            Some(value) => {
                check_presence(field, value, &p, issues);
                validate_ty(value, &field.ty, &p, issues);
            }
        }
    }
}

fn check_presence(field: &Field, value: &Value, ptr: &str, issues: &mut Vec<Issue>) {
    // Required and `optional` fields may carry their default value.
    // Implicit-presence fields may not, unless they are message-typed, where
    // presence is tracked independently of content.
    if field.behavior != Behavior::Implicit || !field.ty.default_is_omittable() {
        return;
    }
    if is_default(value, &field.ty) {
        issues.push(Issue::new(
            Code::PresenceInvalid,
            ptr,
            "member holds its default value and has implicit presence, so A2A \
             §8.4.1 requires it to be omitted before canonicalization"
                .to_string(),
        ));
    }
}

fn is_default(v: &Value, ty: &Ty) -> bool {
    match ty {
        Ty::Str => v.as_str() == Some(""),
        Ty::Bool => v.as_bool() == Some(false),
        Ty::Repeated(_) => v.as_array().is_some_and(|a| a.is_empty()),
        Ty::Map(_) => v.as_object().is_some_and(|o| o.is_empty()),
        Ty::Msg(_) | Ty::Struct => false,
    }
}

fn validate_ty(v: &Value, ty: &Ty, ptr: &str, issues: &mut Vec<Issue>) {
    match ty {
        Ty::Str => {
            if !v.is_string() {
                issues.push(Issue::new(Code::CardInvalid, ptr, "expected a string"));
            }
        }
        Ty::Bool => {
            if !v.is_boolean() {
                issues.push(Issue::new(Code::CardInvalid, ptr, "expected a boolean"));
            }
        }
        Ty::Struct => {
            if !v.is_object() {
                issues.push(Issue::new(Code::CardInvalid, ptr, "expected an object"));
            }
        }
        Ty::Msg(m) => validate_msg(v, m, ptr, issues),
        Ty::Repeated(inner) => match v.as_array() {
            None => issues.push(Issue::new(Code::CardInvalid, ptr, "expected an array")),
            Some(items) => {
                for (i, item) in items.iter().enumerate() {
                    validate_ty(item, inner, &format!("{ptr}/{i}"), issues);
                }
            }
        },
        Ty::Map(inner) => match v.as_object() {
            None => issues.push(Issue::new(Code::CardInvalid, ptr, "expected an object")),
            Some(entries) => {
                for (k, item) in entries {
                    validate_ty(item, inner, &child(ptr, k), issues);
                }
            }
        },
    }
}

/// Append one RFC 6901 reference token to a JSON Pointer.
fn child(ptr: &str, token: &str) -> String {
    format!("{ptr}/{}", token.replace('~', "~0").replace('/', "~1"))
}
