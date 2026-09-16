//! Schema and field-presence validation, per `SPEC.md` §5.2 and A2A §8.4.1.
//!
//! The registry validates that a submitted card already satisfies the presence
//! rules; it never rewrites the card. Rewriting would change bytes the client
//! has already signed.

use serde_json::Value;

use crate::error::{Code, Issue};
use crate::schema::{AGENT_CARD, Behavior, Field, Msg, Ty};

/// The most issues one validation will collect.
///
/// A complete list helps someone fixing a card by hand; an unbounded one is an
/// amplifier, since a caller controls how many problems a document contains and
/// each costs two heap allocations. Nobody reads the fiftieth.
pub const MAX_ISSUES: usize = 50;

/// A bounded sink for issues.
///
/// The bound used to be a `if issues.len() >= MAX_ISSUES` guard repeated at the
/// call sites that were thought to matter, and two loops did not have one: a
/// half-megabyte document of unknown members still produced tens of thousands
/// of issues. Making the *container* refuse to grow removes the possibility of
/// forgetting, which is the only version of this bound that stays true as the
/// schema walker changes.
#[derive(Default)]
struct Issues {
    items: Vec<Issue>,
}

impl Issues {
    fn push(&mut self, issue: Issue) {
        if self.items.len() < MAX_ISSUES {
            self.items.push(issue);
        }
    }

    /// Whether the cap is reached. Callers use it to stop *walking*, not merely
    /// to stop recording: the walk itself is the cost being bounded.
    fn is_full(&self) -> bool {
        self.items.len() >= MAX_ISSUES
    }
}

/// Validate a value against the pinned `AgentCard` schema.
///
/// Returns up to [`MAX_ISSUES`] issues rather than only the first, so a
/// publishing interface can show a usable list.
pub fn validate_card(v: &Value) -> Vec<Issue> {
    let mut issues = Issues::default();
    validate_msg(v, &AGENT_CARD, "", &mut issues);
    issues.items
}

fn validate_msg(v: &Value, msg: &Msg, ptr: &str, issues: &mut Issues) {
    if issues.is_full() {
        return;
    }
    let Some(obj) = v.as_object() else {
        issues.push(Issue::new(
            Code::CardInvalid,
            ptr,
            format!("expected an object for {}", msg.name),
        ));
        return;
    };

    for key in obj.keys() {
        if issues.is_full() {
            return;
        }
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
        if issues.is_full() {
            return;
        }
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

fn check_presence(field: &Field, value: &Value, ptr: &str, issues: &mut Issues) {
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

fn validate_ty(v: &Value, ty: &Ty, ptr: &str, issues: &mut Issues) {
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
                    if issues.is_full() {
                        return;
                    }
                    validate_ty(item, inner, &format!("{ptr}/{i}"), issues);
                }
            }
        },
        Ty::Map(inner) => match v.as_object() {
            None => issues.push(Issue::new(Code::CardInvalid, ptr, "expected an object")),
            Some(entries) => {
                for (k, item) in entries {
                    if issues.is_full() {
                        return;
                    }
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

/// Restore every `REQUIRED` member a proto3 JSON encoder omitted because it
/// held its default value — A2A §8.4.1 rule 1, which the proto3 JSON mapping
/// itself does not apply.
///
/// This is for the *authoring* side only: a card produced from typed values by
/// an encoder that follows the standard mapping (the official SDK's
/// `protojson` layer does) comes out without `"description": ""`, `"skills": []`
/// or `"tags": []`, and would be refused by [`validate_card`]. It adds members;
/// it never removes, renames or reshapes one, and it is table-driven, so it
/// cannot disagree with the table [`validate_card`] checks against.
///
/// The registry never calls this: it does not rewrite a card it received.
pub fn complete_required(v: &mut Value) {
    complete_msg(v, &AGENT_CARD);
}

fn complete_msg(v: &mut Value, msg: &Msg) {
    let Some(obj) = v.as_object_mut() else { return };
    for f in msg.fields {
        if !msg.is_oneof && f.behavior == Behavior::Required && !obj.contains_key(f.name) {
            obj.insert(f.name.to_string(), default_of(&f.ty));
        }
        if let Some(child) = obj.get_mut(f.name) {
            complete_ty(child, &f.ty);
        }
    }
}

fn complete_ty(v: &mut Value, ty: &Ty) {
    match ty {
        Ty::Msg(m) => complete_msg(v, m),
        Ty::Repeated(inner) => {
            if let Some(items) = v.as_array_mut() {
                items.iter_mut().for_each(|x| complete_ty(x, inner));
            }
        }
        Ty::Map(inner) => {
            if let Some(entries) = v.as_object_mut() {
                entries.values_mut().for_each(|x| complete_ty(x, inner));
            }
        }
        Ty::Str | Ty::Bool | Ty::Struct => {}
    }
}

fn default_of(ty: &Ty) -> Value {
    match ty {
        Ty::Str => Value::String(String::new()),
        Ty::Bool => Value::Bool(false),
        Ty::Repeated(_) => Value::Array(Vec::new()),
        Ty::Map(_) | Ty::Struct => Value::Object(serde_json::Map::new()),
        Ty::Msg(m) => {
            let mut o = Value::Object(serde_json::Map::new());
            complete_msg(&mut o, m);
            o
        }
    }
}

#[cfg(test)]
mod complete_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn restores_required_defaults_and_nothing_else() {
        let mut v = json!({
            "capabilities": {}, "defaultInputModes": ["a"], "defaultOutputModes": ["a"],
            "name": "A", "supportedInterfaces": [{"protocolBinding": "JSONRPC", "protocolVersion": "1.0", "url": "https://a"}],
            "version": "1", "skills": [{"id": "s", "name": "S"}]
        });
        complete_required(&mut v);
        assert_eq!(v["description"], json!(""));
        assert_eq!(v["skills"][0]["description"], json!(""));
        assert_eq!(v["skills"][0]["tags"], json!([]));
        assert!(
            v.get("provider").is_none(),
            "an implicit member is never invented"
        );
        assert!(
            v.get("iconUrl").is_none(),
            "an optional member is never invented"
        );
        assert!(validate_card(&v).is_empty());
    }

    #[test]
    fn a_complete_card_is_left_untouched() {
        let mut v = json!({
            "capabilities": {}, "defaultInputModes": ["a"], "defaultOutputModes": ["a"], "description": "d",
            "name": "A", "supportedInterfaces": [{"protocolBinding": "JSONRPC", "protocolVersion": "1.0", "url": "https://a"}],
            "version": "1", "skills": []
        });
        let before = v.clone();
        complete_required(&mut v);
        assert_eq!(v, before);
    }
}
