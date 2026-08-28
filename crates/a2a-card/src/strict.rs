//! Strict JSON parsing, per `SPEC.md` §5.1.
//!
//! `serde_json` is permissive in two ways that silently break signatures:
//! it keeps the *last* of two duplicate members, and it accepts integers
//! outside the range where a JSON number round-trips through an IEEE-754
//! double. In both cases the value the registry ends up canonicalizing is not
//! the value the client signed, and the only symptom is an unexplainable
//! signature failure. This module turns both into precise, early errors.

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::error::{CardError, Code, Issue};

/// 2^53 - 1: the largest integer that survives a round trip through a double.
pub const MAX_SAFE_INTEGER: i128 = 9_007_199_254_740_991;

/// Parse JSON text under the strict profile of §5.1.
pub fn parse(input: &str) -> Result<Value, CardError> {
    let mut de = serde_json::Deserializer::from_str(input);
    let StrictValue(v) = StrictValue::deserialize(&mut de)
        .map_err(|e| CardError::Json(Issue::new(Code::JsonInvalid, "", e.to_string())))?;
    de.end().map_err(|e| {
        CardError::Json(Issue::new(
            Code::JsonInvalid,
            "",
            format!("trailing content: {e}"),
        ))
    })?;
    Ok(v)
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value in the I-JSON domain")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_bool<E>(self, b: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(b)))
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(s.to_owned())))
    }

    fn visit_string<E>(self, s: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(s)))
    }

    fn visit_i64<E: de::Error>(self, n: i64) -> Result<Self::Value, E> {
        check_integer(n as i128).map_err(E::custom)?;
        Ok(StrictValue(Value::from(n)))
    }

    fn visit_u64<E: de::Error>(self, n: u64) -> Result<Self::Value, E> {
        check_integer(n as i128).map_err(E::custom)?;
        Ok(StrictValue(Value::from(n)))
    }

    fn visit_i128<E: de::Error>(self, n: i128) -> Result<Self::Value, E> {
        check_integer(n).map_err(E::custom)?;
        Ok(StrictValue(Value::from(n as i64)))
    }

    fn visit_u128<E: de::Error>(self, n: u128) -> Result<Self::Value, E> {
        check_integer(
            i128::try_from(n).map_err(|_| E::custom("integer out of the I-JSON domain"))?,
        )
        .map_err(E::custom)?;
        Ok(StrictValue(Value::from(n as u64)))
    }

    fn visit_f64<E: de::Error>(self, n: f64) -> Result<Self::Value, E> {
        if !n.is_finite() {
            return Err(E::custom(
                "non-finite numbers are outside the I-JSON domain",
            ));
        }
        // An integer literal too large for `u64` never reaches `visit_u64` — it
        // arrives here, already a double, and so escaped the range check that
        // every smaller integer gets. serde_json does not hand over the original
        // token, so the literal `10000000000000000000000` and the literal `1e22`
        // are the same value by the time this sees them.
        //
        // Both are refused. The first is what §5.1 forbids; the second is
        // legal I-JSON but indistinguishable from it here, and a card carrying
        // an integral magnitude above 2^53 is either lossy or a number no agent
        // card has any business holding. Over-refusing in that corner is the
        // safe direction: it rejects a document, where under-refusing accepts
        // one whose value silently changed.
        if n.fract() == 0.0 && n.abs() > MAX_SAFE_INTEGER as f64 {
            return Err(E::custom(format!(
                "integral value {n:?} is outside the I-JSON safe range (±{MAX_SAFE_INTEGER})"
            )));
        }
        // The symmetric case at the small end. A subnormal has lost precision
        // before anything here sees it, so it is refused.
        //
        // What this cannot catch: a literal small enough to underflow all the
        // way to zero, such as `1e-400`. serde_json hands over the `f64`, not
        // the token, so by the time this runs it is indistinguishable from a
        // plainly written `0.0` — and refusing every float zero would reject a
        // legal, ordinary value. The consequence is bounded and worth stating:
        // such a literal is canonicalized to `0`, so the published document is
        // not the one written. It is *not* a signature problem — a publisher and
        // a verifier canonicalize through the same rule and agree — which is why
        // this is left rather than solved with a hand-rolled number parser.
        if n != 0.0 && n.abs() < f64::MIN_POSITIVE {
            return Err(E::custom(format!(
                "number {n:?} is subnormal and outside the I-JSON domain"
            )));
        }
        Ok(StrictValue(Value::from(n)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(StrictValue(v)) = seq.next_element::<StrictValue>()? {
            out.push(v);
        }
        Ok(StrictValue(Value::Array(out)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let StrictValue(value) = map.next_value::<StrictValue>()?;
            if out.insert(key.clone(), value).is_some() {
                // RFC 8785 assumes member names are unique. Keeping the last
                // one, as most parsers do, changes the canonical bytes.
                return Err(de::Error::custom(format!("duplicate member name {key:?}")));
            }
        }
        Ok(StrictValue(Value::Object(out)))
    }
}

fn check_integer(n: i128) -> Result<(), String> {
    if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&n) {
        return Err(format!(
            "integer {n} is outside the I-JSON safe range (±{MAX_SAFE_INTEGER})"
        ));
    }
    Ok(())
}
