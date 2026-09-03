//! Shared helpers for the `psrp-rs` fuzz targets.
//!
//! Three things live here:
//!
//! * [`ArbValue`] / [`SafeValue`] — `Arbitrary` generators that produce
//!   real [`PsValue`] trees instead of random bytes, so the round-trip
//!   targets explore the *encoder* as well as the decoder.
//! * [`normalize`] / [`eq_lossy`] — the exact set of transformations the
//!   CLIXML codec is allowed to apply to a value, so a round-trip target
//!   asserts something true rather than something flaky.
//! * [`wire`] — builders for PSRP messages and fragments, used by the
//!   targets that feed the runspace pool.

use arbitrary::{Arbitrary, Result as ArbResult, Unstructured};
use psrp_rs::clixml::{PsObject, PsValue};

/// Maximum nesting depth of a generated value.
///
/// The *decoder* is the attacker-facing side and is fuzzed on raw input
/// by `clixml_decoder`; the encoder only ever sees values we built
/// ourselves, so there is no reason to generate 1000-deep trees here.
pub const MAX_DEPTH: u32 = 6;

/// Characters used by [`SafeValue`] strings.
///
/// Everything in here is chosen to hit a lossy path the codec has
/// actually had: the XML metacharacters, `\t` / `\n` / `\r` (attribute
/// value normalisation), and `_` + `x` + hex digits, which can spell a
/// literal `_xHHHH_` that the decoder would otherwise read as an escape.
const SAFE_CHARS: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .-/:+<>&\"'_x\t\n\r";

// =====================================================================
// Generators
// =====================================================================

/// An unrestricted [`PsValue`]: every variant, arbitrary strings,
/// arbitrary floats. Used by the targets that only assert "no panic" or
/// "the codec reaches a fixed point".
#[derive(Debug)]
pub struct ArbValue(pub PsValue);

/// A [`PsValue`] restricted to the shapes that are guaranteed to survive
/// `to_clixml` → `parse_clixml` exactly (after [`normalize`]).
///
/// The restrictions, and why each one exists:
///
/// * strings draw from [`SAFE_CHARS`] — `escape` turns control chars
///   into `_xHHHH_` and the decoder turns `_xHHHH_` back into a char, so
///   a string that *already* contains such a sequence is not a fixed
///   point of the codec;
/// * `PsValue::Decimal` bodies never start or end with whitespace,
///   because the decoder trims `<D>`;
/// * objects never carry a `to_string` (the encoder writes `<ToString>`,
///   the decoder drops it) nor a `_value` property holding a *scalar*
///   (the encoder renders `_value` as a bare child, and the decoder only
///   picks bare children back up for `<LST>` and `<DCT>`).
#[derive(Debug)]
pub struct SafeValue(pub PsValue);

impl<'a> Arbitrary<'a> for ArbValue {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self(gen_value(u, MAX_DEPTH, false)?))
    }
}

impl<'a> Arbitrary<'a> for SafeValue {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self(gen_value(u, MAX_DEPTH, true)?))
    }
}

fn gen_string(u: &mut Unstructured<'_>, safe: bool) -> ArbResult<String> {
    if !safe {
        return u.arbitrary();
    }
    let len = u.int_in_range(0..=16usize)?;
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        let idx = u.int_in_range(0..=SAFE_CHARS.len() - 1)?;
        s.push(SAFE_CHARS[idx] as char);
    }
    Ok(s)
}

fn gen_value(u: &mut Unstructured<'_>, depth: u32, safe: bool) -> ArbResult<PsValue> {
    // Below the depth budget (or once the input is exhausted) only
    // scalars are produced, which keeps generation total.
    let scalars_only = depth == 0 || u.is_empty();
    let last = if scalars_only { 21 } else { 24 };
    Ok(match u.int_in_range(0..=last)? {
        0 => PsValue::Null,
        1 => PsValue::Bool(u.arbitrary()?),
        2 => PsValue::I8(u.arbitrary()?),
        3 => PsValue::U8(u.arbitrary()?),
        4 => PsValue::I16(u.arbitrary()?),
        5 => PsValue::U16(u.arbitrary()?),
        6 => PsValue::I32(u.arbitrary()?),
        7 => PsValue::U32(u.arbitrary()?),
        8 => PsValue::I64(u.arbitrary()?),
        9 => PsValue::U64(u.arbitrary()?),
        10 => PsValue::F32(f32::from_bits(u.arbitrary()?)),
        11 => PsValue::Double(f64::from_bits(u.arbitrary()?)),
        12 => PsValue::Decimal(gen_decimal(u, safe)?),
        13 => PsValue::Char(u.arbitrary()?),
        14 => PsValue::String(gen_string(u, safe)?),
        15 => PsValue::Bytes(u.arbitrary()?),
        16 => PsValue::DateTime(gen_string(u, safe)?),
        17 => PsValue::Duration(gen_string(u, safe)?),
        18 => PsValue::Guid(uuid::Uuid::from_bytes(u.arbitrary()?)),
        19 => PsValue::Version(gen_string(u, safe)?),
        20 => PsValue::Uri(gen_string(u, safe)?),
        21 => PsValue::Xml(gen_string(u, safe)?),
        22 => {
            let n = u.int_in_range(0..=4usize)?;
            let mut items = Vec::with_capacity(n);
            for _ in 0..n {
                items.push(gen_value(u, depth - 1, safe)?);
            }
            PsValue::List(items)
        }
        23 => {
            let n = u.int_in_range(0..=3usize)?;
            let mut entries = Vec::with_capacity(n);
            for _ in 0..n {
                entries.push((gen_value(u, depth - 1, safe)?, gen_value(u, depth - 1, safe)?));
            }
            PsValue::Dict(entries)
        }
        _ => PsValue::Object(gen_object(u, depth, safe)?),
    })
}

fn gen_decimal(u: &mut Unstructured<'_>, safe: bool) -> ArbResult<String> {
    let s = gen_string(u, safe)?;
    // `<D>` is trimmed by the decoder, so a safe value must already be
    // trimmed. (Unsafe values are free to have whatever whitespace.)
    Ok(if safe { s.trim().to_string() } else { s })
}

fn gen_object(u: &mut Unstructured<'_>, depth: u32, safe: bool) -> ArbResult<PsObject> {
    let mut obj = PsObject::new();

    let tn = u.int_in_range(0..=2usize)?;
    for _ in 0..tn {
        obj.type_names.push(gen_string(u, safe)?);
    }

    let props = u.int_in_range(0..=4usize)?;
    for _ in 0..props {
        let mut name = gen_string(u, safe)?;
        if safe && name == "_value" {
            // Reserved: the encoder renders `_value` as a bare child.
            name.push('x');
        }
        obj.properties.insert(name, gen_value(u, depth - 1, safe)?);
    }

    if !safe && u.arbitrary()? {
        obj.to_string = Some(gen_string(u, safe)?);
    }

    Ok(obj)
}

// =====================================================================
// Round-trip semantics
// =====================================================================

/// Apply the transformations the CLIXML codec is *allowed* to perform,
/// so that `normalize(v)` is a fixed point of `to_clixml`/`parse_clixml`.
///
/// The only such transformation is container wrapping: a bare
/// `PsValue::List` / `PsValue::Dict` is written as
/// `<Obj><LST>…</LST></Obj>`, which the decoder reads back as an object
/// carrying the container under the synthetic `_value` property.
#[must_use]
pub fn normalize(value: &PsValue) -> PsValue {
    match value {
        PsValue::List(items) => {
            let inner = PsValue::List(items.iter().map(normalize).collect());
            wrap(inner)
        }
        PsValue::Dict(entries) => {
            let inner = PsValue::Dict(
                entries
                    .iter()
                    .map(|(k, v)| (normalize(k), normalize(v)))
                    .collect(),
            );
            wrap(inner)
        }
        PsValue::Object(obj) => {
            let mut out = PsObject::new();
            out.type_names.clone_from(&obj.type_names);
            for (k, v) in &obj.properties {
                out.properties.insert(k.clone(), normalize(v));
            }
            PsValue::Object(out)
        }
        other => other.clone(),
    }
}

fn wrap(inner: PsValue) -> PsValue {
    let mut obj = PsObject::new();
    obj.properties.insert("_value".into(), inner);
    PsValue::Object(obj)
}

/// Structural equality that treats `NaN == NaN` as true.
///
/// `f64::NAN != f64::NAN`, but `NaN` *does* survive the codec (the
/// encoder writes `NaN`, the decoder parses it back), so plain
/// `PartialEq` would report a false round-trip failure.
#[must_use]
pub fn eq_lossy(a: &PsValue, b: &PsValue) -> bool {
    match (a, b) {
        (PsValue::Double(x), PsValue::Double(y)) => x == y || (x.is_nan() && y.is_nan()),
        (PsValue::F32(x), PsValue::F32(y)) => x == y || (x.is_nan() && y.is_nan()),
        (PsValue::List(x), PsValue::List(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| eq_lossy(p, q))
        }
        (PsValue::Dict(x), PsValue::Dict(y)) => {
            x.len() == y.len()
                && x.iter()
                    .zip(y)
                    .all(|((k1, v1), (k2, v2))| eq_lossy(k1, k2) && eq_lossy(v1, v2))
        }
        (PsValue::Object(x), PsValue::Object(y)) => {
            x.type_names == y.type_names
                && x.properties.len() == y.properties.len()
                && x.properties
                    .iter()
                    .zip(y.properties.iter())
                    .all(|((k1, v1), (k2, v2))| k1 == k2 && eq_lossy(v1, v2))
        }
        _ => a == b,
    }
}

// =====================================================================
// PSRP wire builders
// =====================================================================

pub mod wire {
    use psrp_rs::fragment::encode_message;
    use psrp_rs::message::{Destination, MessageType, PsrpMessage};
    use uuid::Uuid;

    /// Encode one PSRP message and wrap it in a single fragment stream.
    #[must_use]
    pub fn message(
        object_id: u64,
        destination: Destination,
        message_type: MessageType,
        rpid: Uuid,
        pid: Uuid,
        data: &str,
    ) -> Vec<u8> {
        let msg = PsrpMessage {
            destination,
            message_type,
            rpid,
            pid,
            data: data.to_string(),
        };
        encode_message(object_id, &msg.encode())
    }

    /// A client-bound message with nil GUIDs — the shape most decoders
    /// in the crate see during a handshake.
    #[must_use]
    pub fn client_message(object_id: u64, message_type: MessageType, data: &str) -> Vec<u8> {
        message(
            object_id,
            Destination::Client,
            message_type,
            Uuid::nil(),
            Uuid::nil(),
            data,
        )
    }
}

// =====================================================================
// Async support
// =====================================================================

/// A process-wide current-thread Tokio runtime.
///
/// Building a runtime per iteration would dominate the fuzzing budget;
/// a single-threaded shared one keeps iterations cheap and deterministic.
#[must_use]
pub fn runtime() -> &'static tokio::runtime::Runtime {
    use std::sync::OnceLock;
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("current-thread runtime")
    })
}
