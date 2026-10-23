//! CLIXML decoder.
//!
//! Tolerant: unknown elements are skipped; a dangling `<Ref>` decodes to
//! [`PsValue::Null`]; leading whitespace / BOM / `<Objs>` wrappers are
//! accepted transparently.

use std::collections::{HashMap, HashSet};

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use super::{PsObject, PsValue};
use crate::error::{PsrpError, Result};

/// Parse a CLIXML fragment into a sequence of top-level values.
///
/// A single CLIXML body may contain several siblings (a PSRP `PipelineOutput`
/// message, for example, is one `<Obj>` at the top level — but a
/// `SessionCapability` message consists of an `<Obj>` with a `<MS>` of
/// primitive siblings, which this parser also handles).
pub fn parse_clixml(xml: &str) -> Result<Vec<PsValue>> {
    let cleaned = xml.trim_start_matches('\u{FEFF}').trim_start();
    let mut reader = Reader::from_str(cleaned);
    reader.config_mut().trim_text(false);

    let mut state = DecoderState {
        referenced: referenced_ids(cleaned),
        budget: ref_budget(cleaned.len()),
        ..DecoderState::default()
    };
    let mut out: Vec<PsValue> = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) => {
                if let Some(value) = parse_element(&mut reader, &e, &mut state)? {
                    out.push(value);
                }
            }
            Event::Empty(e) => {
                if let Some(value) = parse_empty(&e, &mut state)? {
                    out.push(value);
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    Ok(out)
}

/// Maximum `<Obj>` / `<LST>` / `<DCT>` nesting accepted from the wire.
///
/// The parser is recursive, and the document comes from the remote host:
/// without a cap, ~10 KiB of `<Obj><MS>` repeated is enough to overflow
/// the stack and **abort the process** — a stack overflow is not a
/// catchable panic, so `forbid(unsafe_code)` buys nothing here.
///
/// 64 was measured as the deepest level that still fits comfortably in
/// the 2 MiB stack of a Tokio worker thread in a debug build, and it is
/// an order of magnitude more than PowerShell's own serializer ever
/// emits (`Serialization.MaximumDepth` defaults to 1).
pub const MAX_NESTING_DEPTH: u32 = 64;

/// Floor, ceiling and per-byte allowance of the weight (see [`measure`]) that
/// the references of one document may materialize.
///
/// A reference is resolved by cloning the object it points to, so a server
/// can chain a few dozen objects that each hold two references to the
/// previous one: ~1 KiB of XML then expands to 2^n values and exhausts the
/// memory (the process aborts, it is not a catchable error). Legitimate
/// sharing grows with the document (a collection whose elements share one
/// object), hence an allowance per byte of XML on top of the floor, and the
/// ceiling keeps the worst case near a gigabyte (a value costs at most
/// ~112 bytes per unit of weight; text is cheaper).
const REF_BUDGET_FLOOR: u64 = 1 << 20;
const REF_BUDGET_CEILING: u64 = 8 << 20;
const REF_BUDGET_PER_BYTE: u64 = 8;

fn ref_budget(xml_len: usize) -> u64 {
    REF_BUDGET_FLOOR
        .saturating_add((xml_len as u64).saturating_mul(REF_BUDGET_PER_BYTE))
        .min(REF_BUDGET_CEILING)
}

/// The `RefId`s that some `<Ref>` of the document points to.
///
/// Only those objects are kept for a later reference, so that an object
/// nobody references is not cloned (once per enclosing object that has a
/// `RefId`, which is all of them in PowerShell's output). A malformed
/// document ends the scan early; the real parse reports the error.
fn referenced_ids(xml: &str) -> HashSet<String> {
    let mut reader = Reader::from_str(xml);
    let mut ids = HashSet::new();
    let mut buf = Vec::new();
    while let Ok(event) = reader.read_event_into(&mut buf) {
        match event {
            Event::Start(e) | Event::Empty(e) if e.name().as_ref() == "Ref" => {
                if let Ok(Some(id)) = ref_ref_id_attr(&e) {
                    ids.insert(id);
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    ids
}

#[derive(Default)]
struct DecoderState {
    /// Objects that a `<Ref>` points to, by `RefId` (see [`referenced_ids`]).
    refs: HashMap<String, PsValue>,
    referenced: HashSet<String>,
    /// Weight materialized by references so far, bounded by `budget`.
    expanded: u64,
    budget: u64,
    type_names: HashMap<String, Vec<String>>,
    /// Current nesting level, maintained by [`parse_element`].
    depth: u32,
}

impl DecoderState {
    /// Charge `weight` to the reference budget, or fail when it is spent.
    fn charge(&mut self, weight: u64) -> Result<()> {
        let expanded = self.expanded.saturating_add(weight);
        if expanded > self.budget {
            return Err(PsrpError::clixml(format!(
                "CLIXML <Ref> expansion exceeds {}",
                self.budget
            )));
        }
        self.expanded = expanded;
        Ok(())
    }
}

/// Read the `N="…"` property-name attribute.
///
/// The value is XML-unescaped and then run through the PowerShell
/// `_xHHHH_` decoder, mirroring exactly what `encode::escape` did on the
/// way out. Skipping either step corrupts any property name containing
/// `&`, `<`, `>`, `"`, `'` or a control character — and because the
/// re-encoder escapes the result again, the damage compounds on every
/// hop (`&lt;` becomes `&amp;lt;` becomes `&amp;amp;lt;` …).
fn name_attr(e: &BytesStart) -> Result<Option<String>> {
    for attr in e.attributes().flatten() {
        if attr.key.as_ref() == "N" {
            let unescaped = attr
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .map_err(|err| PsrpError::clixml(err.to_string()))?;
            return Ok(Some(decode_pwsh_escapes(&unescaped)));
        }
    }
    Ok(None)
}

/// Read the `RefId="…"` attribute of an `<Obj>` / `<TN>`.
fn ref_id_attr(e: &BytesStart) -> Result<Option<String>> {
    for attr in e.attributes().flatten() {
        if attr.key.as_ref() == "RefId" {
            let unescaped = attr
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .map_err(|err| PsrpError::clixml(err.to_string()))?;
            return Ok(Some(unescaped.into_owned()));
        }
    }
    Ok(None)
}

/// Read the `RefId="…"` attribute of a `<Ref>` / `<TNRef>`.
fn ref_ref_id_attr(e: &BytesStart) -> Result<Option<String>> {
    ref_id_attr(e)
}

/// Resolve a `<Ref RefId="…"/>` against the objects decoded so far.
///
/// PowerShell writes a second occurrence of an object already serialized
/// in the same graph as exactly this self-closed element
/// (`WritePSObjectReference`), in a list item, a dictionary key or value,
/// a member or at the top level, so every one of those goes through here.
/// A reference with no `RefId`, or to an id not decoded yet (a dangling
/// one, or a cycle back to an object still being built), is `Null`.
///
/// The copy is bounded: by the reference budget over the whole document,
/// and so that, planted `level` containers below the current element, it
/// stays within [`MAX_NESTING_DEPTH`] (a chain of references would
/// otherwise build a value deep enough to overflow the stack of whatever
/// walks it next).
fn resolve_ref(e: &BytesStart, state: &mut DecoderState, level: u32) -> Result<PsValue> {
    let Some(target) = ref_ref_id_attr(e)?.and_then(|r| state.refs.get(&r)) else {
        return Ok(PsValue::Null);
    };
    let (weight, height) = measure(target);
    if state.depth.saturating_add(level).saturating_add(height) > MAX_NESTING_DEPTH {
        return Err(PsrpError::clixml(format!(
            "CLIXML <Ref> would nest deeper than {MAX_NESTING_DEPTH} levels"
        )));
    }
    let value = target.clone();
    state.charge(weight)?;
    Ok(value)
}

/// Rough memory weight and container nesting of a decoded value.
///
/// Every node weighs 1, plus the length of its text or bytes and of the
/// names it carries; the height counts `Object` / `List` / `Dict` levels.
/// Both are over-estimates on purpose: they only bound a copy.
fn measure(v: &PsValue) -> (u64, u32) {
    match v {
        PsValue::String(s)
        | PsValue::Decimal(s)
        | PsValue::DateTime(s)
        | PsValue::Duration(s)
        | PsValue::Version(s)
        | PsValue::Uri(s)
        | PsValue::Xml(s)
        | PsValue::ScriptBlock(s)
        | PsValue::SecureString(s) => (1 + s.len() as u64, 0),
        PsValue::Bytes(b) => (1 + b.len() as u64, 0),
        PsValue::List(items) => items.iter().fold((1, 1), |(w, h), i| {
            let (iw, ih) = measure(i);
            (w + iw, h.max(1 + ih))
        }),
        PsValue::Dict(entries) => entries.iter().fold((1, 1), |(w, h), (k, val)| {
            let (kw, kh) = measure(k);
            let (vw, vh) = measure(val);
            (w + kw + vw, h.max(1 + kh.max(vh)))
        }),
        PsValue::Object(o) => {
            let mut weight = 1 + o.to_string.as_ref().map_or(0, |s| s.len() as u64);
            weight += o.type_names.iter().map(|t| 1 + t.len() as u64).sum::<u64>();
            let mut height = 1;
            for (name, val) in &o.properties {
                let (vw, vh) = measure(val);
                weight += 1 + name.len() as u64 + vw;
                height = height.max(1 + vh);
            }
            (weight, height)
        }
        _ => (1, 0),
    }
}

fn parse_empty(e: &BytesStart, state: &mut DecoderState) -> Result<Option<PsValue>> {
    match e.name().as_ref() {
        "Nil" => Ok(Some(PsValue::Null)),
        "Ref" => resolve_ref(e, state, 1).map(Some),
        "S" => Ok(Some(PsValue::String(String::new()))),
        // PowerShell normally writes an empty value self-closed
        // (`<S N="x" />`, `<SBK N="x" />`: the .NET writer shortens an element
        // with no content), and `<S></S>` only when its output buffer happens
        // to flush before the end tag; both must decode.
        "SBK" | "SCT" => Ok(Some(PsValue::ScriptBlock(String::new()))),
        "ToString" => Ok(None),
        _ => Ok(None),
    }
}

fn parse_int<T>(reader: &mut Reader<&[u8]>, closing: &str) -> Result<T>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    let text = read_text(reader, closing)?;
    text.trim()
        .parse::<T>()
        .map_err(|err| PsrpError::clixml(format!("{closing}: {err}")))
}

fn parse_float(s: &str) -> std::result::Result<f64, String> {
    match s {
        "NaN" => Ok(f64::NAN),
        "Infinity" => Ok(f64::INFINITY),
        "-Infinity" => Ok(f64::NEG_INFINITY),
        other => other.parse::<f64>().map_err(|e| e.to_string()),
    }
}

/// Depth-guarded entry point for element parsing.
///
/// Every recursion cycle in this module passes through here
/// (`parse_element` → `parse_obj_body` → `parse_member_set` /
/// `parse_list` / `parse_dict` → `parse_element`), so one counter is
/// enough to bound them all.
fn parse_element(
    reader: &mut Reader<&[u8]>,
    e: &BytesStart,
    state: &mut DecoderState,
) -> Result<Option<PsValue>> {
    if state.depth >= MAX_NESTING_DEPTH {
        return Err(PsrpError::clixml(format!(
            "CLIXML nested deeper than {MAX_NESTING_DEPTH} levels"
        )));
    }
    state.depth += 1;
    let result = parse_element_inner(reader, e, state);
    state.depth -= 1;
    result
}

fn parse_element_inner(
    reader: &mut Reader<&[u8]>,
    e: &BytesStart,
    state: &mut DecoderState,
) -> Result<Option<PsValue>> {
    let tag = e.name().as_ref().to_string();
    match tag.as_str() {
        "S" => {
            let text = read_text(reader, "S")?;
            Ok(Some(PsValue::String(text)))
        }
        "I32" => {
            let text = read_text(reader, "I32")?;
            let v = text
                .trim()
                .parse::<i32>()
                .map_err(|err| PsrpError::clixml(format!("I32: {err}")))?;
            Ok(Some(PsValue::I32(v)))
        }
        "I64" => {
            let text = read_text(reader, "I64")?;
            let v = text
                .trim()
                .parse::<i64>()
                .map_err(|err| PsrpError::clixml(format!("I64: {err}")))?;
            Ok(Some(PsValue::I64(v)))
        }
        "B" => {
            let text = read_text(reader, "B")?;
            let v = match text.trim().to_ascii_lowercase().as_str() {
                "true" | "1" => true,
                "false" | "0" => false,
                other => return Err(PsrpError::clixml(format!("B: bad bool '{other}'"))),
            };
            Ok(Some(PsValue::Bool(v)))
        }
        "Db" => {
            let text = read_text(reader, "Db")?;
            let v =
                parse_float(text.trim()).map_err(|err| PsrpError::clixml(format!("Db: {err}")))?;
            Ok(Some(PsValue::Double(v)))
        }
        "Sg" => {
            let text = read_text(reader, "Sg")?;
            let v =
                parse_float(text.trim()).map_err(|err| PsrpError::clixml(format!("Sg: {err}")))?;
            Ok(Some(PsValue::F32(v as f32)))
        }
        "SB" => Ok(Some(PsValue::I8(parse_int(reader, "SB")?))),
        "By" => Ok(Some(PsValue::U8(parse_int(reader, "By")?))),
        "I16" => Ok(Some(PsValue::I16(parse_int(reader, "I16")?))),
        "U16" => Ok(Some(PsValue::U16(parse_int(reader, "U16")?))),
        "U32" => Ok(Some(PsValue::U32(parse_int(reader, "U32")?))),
        "U64" => Ok(Some(PsValue::U64(parse_int(reader, "U64")?))),
        "D" => {
            let text = read_text(reader, "D")?;
            Ok(Some(PsValue::Decimal(text.trim().to_string())))
        }
        "C" => {
            let text = read_text(reader, "C")?;
            // A `[char]` is one UTF-16 code unit on the wire
            // (`XmlConvert.ToString((UInt16)c)`), so half of an emoji comes
            // as `<C>55357</C>`: a surrogate is no `char`, and one of them
            // must not fail the whole document, so it reads as U+FFFD (as does
            // a number that is no scalar value at all). A scalar above the
            // plane is still read as that character: PowerShell would not
            // send it, but psrp-rs used to write `<C>128512</C>` for `'😀'`.
            let code: u32 = text
                .trim()
                .parse()
                .map_err(|err| PsrpError::clixml(format!("C: {err}")))?;
            Ok(Some(PsValue::Char(
                char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER),
            )))
        }
        "BA" => {
            let text = read_text(reader, "BA")?;
            let bytes = super::encode::base64_decode(text.trim())
                .ok_or_else(|| PsrpError::clixml("BA: invalid base64".to_string()))?;
            Ok(Some(PsValue::Bytes(bytes)))
        }
        "DT" => {
            let text = read_text(reader, "DT")?;
            Ok(Some(PsValue::DateTime(text)))
        }
        "TS" => {
            let text = read_text(reader, "TS")?;
            Ok(Some(PsValue::Duration(text)))
        }
        "G" => {
            let text = read_text(reader, "G")?;
            let uuid = uuid::Uuid::parse_str(text.trim())
                .map_err(|err| PsrpError::clixml(format!("G: {err}")))?;
            Ok(Some(PsValue::Guid(uuid)))
        }
        "Version" => {
            let text = read_text(reader, "Version")?;
            Ok(Some(PsValue::Version(text)))
        }
        "URI" => {
            let text = read_text(reader, "URI")?;
            Ok(Some(PsValue::Uri(text)))
        }
        "XD" => {
            let text = read_text(reader, "XD")?;
            Ok(Some(PsValue::Xml(text)))
        }
        // `SBK` is PowerShell's tag (MS-PSRP 2.2.5.1.23). `SCT` was never
        // one: it is what psrp-rs itself used to write, still accepted so
        // that such output decodes.
        "SBK" | "SCT" => {
            let text = read_text(reader, &tag)?;
            Ok(Some(PsValue::ScriptBlock(text)))
        }
        "SS" => {
            let text = read_text(reader, "SS")?;
            Ok(Some(PsValue::SecureString(text)))
        }
        "Obj" => {
            let ref_id = ref_id_attr(e)?;
            let obj = parse_obj_body(reader, state)?;
            let value = PsValue::Object(obj);
            if let Some(rid) = ref_id.filter(|r| state.referenced.contains(r)) {
                // A kept copy is memory too: it is charged like the others.
                state.charge(measure(&value).0)?;
                state.refs.insert(rid, value.clone());
            }
            // Flatten: if the object has no properties and no type names
            // but its inline LST/DCT was captured elsewhere we still report
            // the object as-is. Otherwise the caller uses `properties()`.
            Ok(Some(value))
        }
        "Ref" => {
            // The self-closed form is `parse_empty`'s; this is `<Ref ..>…</Ref>`.
            let value = resolve_ref(e, state, 0)?;
            skip_to_end(reader)?;
            Ok(Some(value))
        }
        _ => {
            // Unknown top-level element — skip.
            skip_to_end(reader)?;
            Ok(None)
        }
    }
}

fn parse_obj_body(reader: &mut Reader<&[u8]>, state: &mut DecoderState) -> Result<PsObject> {
    let mut obj = PsObject::new();
    let mut buf = Vec::new();
    let mut embedded: Option<PsValue> = None;
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) => match e.name().as_ref() {
                "MS" | "Props" => {
                    parse_member_set(reader, state, &mut obj, e.name().as_ref().to_string())?;
                }
                "TN" => {
                    let rid = ref_id_attr(&e)?;
                    let names = parse_type_names(reader)?;
                    if let Some(rid) = rid.clone() {
                        state.type_names.insert(rid, names.clone());
                    }
                    obj.type_names = names;
                }
                "TNRef" => {
                    let rid = ref_ref_id_attr(&e)?;
                    skip_to_end(reader)?;
                    if let Some(rid) = rid
                        && let Some(names) = state.type_names.get(&rid)
                    {
                        obj.type_names.clone_from(names);
                    }
                }
                "LST" | "IE" | "QUE" | "STK" => {
                    let items = parse_list(reader, state, e.name().as_ref().to_string())?;
                    embedded = Some(PsValue::List(items));
                }
                "DCT" => {
                    let entries = parse_dict(reader, state)?;
                    embedded = Some(PsValue::Dict(entries));
                }
                // A nameless scalar child: the number of a .NET enum
                // (`<TN>…System.Enum…</TN><ToString>Monday</ToString>
                // <I32>1</I32>`). Anything else unknown is skipped.
                _ => {
                    if let Some(value) = parse_element(reader, &e, state)? {
                        embedded.get_or_insert(value);
                    }
                }
            },
            Event::Empty(e) => match e.name().as_ref() {
                "TNRef" => {
                    let rid = ref_ref_id_attr(&e)?;
                    if let Some(rid) = rid
                        && let Some(names) = state.type_names.get(&rid)
                    {
                        obj.type_names.clone_from(names);
                    }
                }
                "ToString" | "Nil" => {}
                _ => {}
            },
            Event::End(e) if e.name().as_ref() == "Obj" => break,
            Event::Eof => {
                return Err(PsrpError::clixml("unexpected EOF inside <Obj>"));
            }
            _ => {}
        }
        buf.clear();
    }

    // If the object had no <MS> but contained an embedded LST / DCT / scalar,
    // expose it under the synthetic property name "_value" so callers can
    // still retrieve it easily.
    if let Some(v) = embedded
        && obj.properties.is_empty()
    {
        obj.properties.insert("_value".into(), v);
    }

    Ok(obj)
}

fn parse_member_set(
    reader: &mut Reader<&[u8]>,
    state: &mut DecoderState,
    obj: &mut PsObject,
    closing_tag: String,
) -> Result<()> {
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) => {
                let name = name_attr(&e)?.unwrap_or_default();
                if let Some(v) = parse_element(reader, &e, state)? {
                    obj.properties.insert(name, v);
                }
            }
            Event::Empty(e) => match e.name().as_ref() {
                "Nil" => {
                    if let Some(name) = name_attr(&e)? {
                        obj.properties.insert(name, PsValue::Null);
                    }
                }
                _ => {
                    if let Some(v) = parse_empty(&e, state)? {
                        obj.properties.insert(name_attr(&e)?.unwrap_or_default(), v);
                    }
                }
            },
            Event::End(e) if e.name().as_ref() == closing_tag.as_str() => break,
            Event::Eof => return Err(PsrpError::clixml("EOF inside member set")),
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

fn parse_list(
    reader: &mut Reader<&[u8]>,
    state: &mut DecoderState,
    closing_tag: String,
) -> Result<Vec<PsValue>> {
    let mut items = Vec::new();
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) => {
                if let Some(v) = parse_element(reader, &e, state)? {
                    items.push(v);
                }
            }
            Event::Empty(e) => {
                if let Some(v) = parse_empty(&e, state)? {
                    items.push(v);
                }
            }
            Event::End(e) if e.name().as_ref() == closing_tag.as_str() => break,
            Event::Eof => return Err(PsrpError::clixml("EOF inside list")),
            _ => {}
        }
        buf.clear();
    }
    Ok(items)
}

fn parse_dict(
    reader: &mut Reader<&[u8]>,
    state: &mut DecoderState,
) -> Result<Vec<(PsValue, PsValue)>> {
    let mut entries = Vec::new();
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) if e.name().as_ref() == "En" => {
                let (k, v) = parse_dict_entry(reader, state)?;
                entries.push((k, v));
            }
            Event::End(e) if e.name().as_ref() == "DCT" => break,
            Event::Eof => return Err(PsrpError::clixml("EOF inside <DCT>")),
            _ => {}
        }
        buf.clear();
    }
    Ok(entries)
}

fn parse_dict_entry(
    reader: &mut Reader<&[u8]>,
    state: &mut DecoderState,
) -> Result<(PsValue, PsValue)> {
    let mut key = PsValue::Null;
    let mut val = PsValue::Null;
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) => {
                let name = name_attr(&e)?.unwrap_or_default();
                if let Some(v) = parse_element(reader, &e, state)? {
                    match name.as_str() {
                        "Key" => key = v,
                        "Value" => val = v,
                        _ => {}
                    }
                }
            }
            Event::Empty(e) => {
                if let Some(v) = parse_empty(&e, state)? {
                    match name_attr(&e)?.unwrap_or_default().as_str() {
                        "Key" => key = v,
                        "Value" => val = v,
                        _ => {}
                    }
                }
            }
            Event::End(e) if e.name().as_ref() == "En" => break,
            Event::Eof => return Err(PsrpError::clixml("EOF inside <En>")),
            _ => {}
        }
        buf.clear();
    }
    Ok((key, val))
}

fn parse_type_names(reader: &mut Reader<&[u8]>) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) if e.name().as_ref() == "T" => {
                let text = read_text(reader, "T")?;
                out.push(text);
            }
            Event::End(e) if e.name().as_ref() == "TN" => break,
            Event::Eof => return Err(PsrpError::clixml("EOF inside <TN>")),
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

fn read_text(reader: &mut Reader<&[u8]>, closing: &str) -> Result<String> {
    let mut out = String::new();
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Text(t) => {
                out.push_str(&t);
            }
            Event::GeneralRef(r) => {
                if let Some(c) = r
                    .resolve_char_ref()
                    .map_err(|e| PsrpError::clixml(e.to_string()))?
                {
                    out.push(c);
                } else {
                    let name: &str = r.as_ref();
                    match quick_xml::escape::resolve_predefined_entity(name) {
                        Some(s) => out.push_str(s),
                        None => {
                            return Err(PsrpError::clixml(format!(
                                "unknown entity reference &{name};"
                            )));
                        }
                    }
                }
            }
            Event::CData(c) => {
                out.push_str(c.as_ref());
            }
            Event::End(e) if e.name().as_ref() == closing => break,
            Event::Eof => {
                return Err(PsrpError::clixml(format!("EOF reading <{closing}>")));
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(decode_pwsh_escapes(&out))
}

/// Drain everything up to the end tag that closes the current element.
///
/// Iterative on purpose — this is the escape hatch for *unknown*
/// elements, so it must stay bounded by the input size rather than by
/// the stack. The counter saturates instead of wrapping so that a
/// pathologically long run of start tags cannot overflow it.
fn skip_to_end(reader: &mut Reader<&[u8]>) -> Result<()> {
    let mut depth: usize = 1;
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(_) => depth = depth.saturating_add(1),
            Event::End(_) => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

/// Decode the `_xHHHH_` escapes PowerShell emits (`EncodeString`).
///
/// Each escape is one UTF-16 code unit, and a character outside the BMP is
/// written as the escapes of its surrogate pair (`_xD83D__xDE00_` is
/// U+1F600), so a run of consecutive escapes is decoded as UTF-16. A
/// surrogate without its other half becomes U+FFFD: .NET's
/// `XmlConvert.DecodeName` yields the lone code unit, which a Rust
/// `String` cannot hold.
///
/// An escape is exactly `_x`, four hex digits of either case, and `_`.
/// A leading `+` in place of the first digit is tolerated (`_x+041_` is
/// `A`, an accident of `from_str_radix` kept for compatibility). `_X` and
/// the eight-digit form `_xHHHHHHHH_`, which `DecodeName` also accepts
/// but PowerShell never emits, are left as text.
fn decode_pwsh_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut units: Vec<u16> = Vec::new();
    let mut rest = s;
    loop {
        if let Some((unit, tail)) = split_pwsh_escape(rest) {
            units.push(unit);
            rest = tail;
            continue;
        }
        // Not an escape: the run so far ends here. Decode it, then copy
        // the text up to the next `_`, the only character that can open
        // an escape (the first one goes whatever it is: it opens none).
        if !units.is_empty() {
            out.extend(
                char::decode_utf16(units.drain(..))
                    .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)),
            );
        }
        let mut chars = rest.chars();
        let Some(first) = chars.next() else {
            break;
        };
        let after = chars.as_str();
        let (text, tail) = after
            .split_at_checked(after.find('_').unwrap_or(after.len()))
            .unwrap_or((after, ""));
        out.push(first);
        out.push_str(text);
        rest = tail;
    }
    out
}

/// The code unit of the `_xHHHH_` escape that starts `s`, and the text
/// after it.
fn split_pwsh_escape(s: &str) -> Option<(u16, &str)> {
    let hex = s.get(..7)?.strip_prefix("_x")?.strip_suffix('_')?;
    let unit = u16::from_str_radix(hex, 16).ok()?;
    Some((unit, s.get(7..)?))
}

#[cfg(test)]
mod tests {
    /// Regression (found while fuzzing `clixml_decoder`): the parser is
    /// recursive and the document is attacker-controlled, so ~10 KiB of
    /// `<Obj><MS>` used to overflow the stack and abort the process.
    #[test]
    fn deep_nesting_is_rejected_not_fatal() {
        use super::super::parse_clixml;
        use super::MAX_NESTING_DEPTH;

        let deep = |n: usize| "<Obj><MS>".repeat(n) + "<Nil/>" + &"</MS></Obj>".repeat(n);

        // Comfortably inside the limit: still parses.
        parse_clixml(&deep(MAX_NESTING_DEPTH as usize / 2)).expect("shallow document");

        // Past it: a structured error, never a crash.
        let err = parse_clixml(&deep(MAX_NESTING_DEPTH as usize + 5))
            .expect_err("over-deep document must be rejected");
        assert!(
            err.to_string().contains("nested deeper"),
            "unexpected error: {err}"
        );

        // And the pathological case that used to abort the process.
        assert!(parse_clixml(&deep(20_000)).is_err());
    }

    // Regression (found by the `clixml_encode_decode` fuzz target):
    // attribute values used to be taken raw, so a property name holding
    // an XML metacharacter came back still escaped — and the encoder
    // then escaped it again on the next hop.
    #[test]
    fn property_names_are_xml_unescaped() {
        use super::super::{PsObject, PsValue, parse_clixml, to_clixml};

        let value = PsValue::Object(
            PsObject::new()
                .with("a<b", PsValue::I32(1))
                .with("x&y", PsValue::I32(2))
                .with("q\"r", PsValue::I32(3)),
        );

        let xml = to_clixml(&value);
        let decoded = parse_clixml(&xml).expect("decodes");
        assert_eq!(decoded[0], value, "property names were mangled");

        // And the damage must not compound across hops.
        let again = parse_clixml(&to_clixml(&decoded[0])).expect("decodes");
        assert_eq!(again[0], value);
    }

    #[test]
    fn property_names_decode_pwsh_escapes() {
        use super::super::{PsObject, PsValue, parse_clixml, to_clixml};

        // `escape` turns control characters in a name into `_xHHHH_`;
        // the decoder has to turn them back.
        let value = PsValue::Object(PsObject::new().with("a\u{1}b", PsValue::Null));
        let xml = to_clixml(&value);
        assert!(xml.contains("_x0001_"), "encoder did not escape: {xml}");
        let decoded = parse_clixml(&xml).expect("decodes");
        assert_eq!(decoded[0], value);
    }

    use super::super::encode::to_clixml;
    use super::*;

    #[test]
    fn primitives() {
        let cases = vec![
            ("<S>hi</S>", PsValue::String("hi".into())),
            ("<I32>-5</I32>", PsValue::I32(-5)),
            ("<I64>99</I64>", PsValue::I64(99)),
            ("<B>true</B>", PsValue::Bool(true)),
            ("<B>false</B>", PsValue::Bool(false)),
            ("<Db>1.5</Db>", PsValue::Double(1.5)),
            ("<Nil/>", PsValue::Null),
        ];
        for (xml, expected) in cases {
            let got = parse_clixml(xml).unwrap();
            assert_eq!(got.len(), 1, "{xml}");
            assert_eq!(got[0], expected, "{xml}");
        }
    }

    #[test]
    fn double_special_values() {
        assert!(
            matches!(parse_clixml("<Db>NaN</Db>").unwrap()[0], PsValue::Double(v) if v.is_nan())
        );
        assert!(matches!(
            parse_clixml("<Db>Infinity</Db>").unwrap()[0],
            PsValue::Double(v) if v.is_infinite() && v.is_sign_positive()
        ));
        assert!(matches!(
            parse_clixml("<Db>-Infinity</Db>").unwrap()[0],
            PsValue::Double(v) if v.is_infinite() && v.is_sign_negative()
        ));
    }

    #[test]
    fn bool_accepts_1_and_0() {
        assert_eq!(parse_clixml("<B>1</B>").unwrap()[0], PsValue::Bool(true));
        assert_eq!(parse_clixml("<B>0</B>").unwrap()[0], PsValue::Bool(false));
    }

    #[test]
    fn bad_bool_errors() {
        assert!(parse_clixml("<B>maybe</B>").is_err());
    }

    #[test]
    fn bad_int_errors() {
        assert!(parse_clixml("<I32>not-a-number</I32>").is_err());
        assert!(parse_clixml("<I64>xx</I64>").is_err());
        assert!(parse_clixml("<Db>oops</Db>").is_err());
    }

    #[test]
    fn escapes_and_bom() {
        let xml = "\u{FEFF}  <S>&lt;hi&amp;&gt;</S>";
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got[0], PsValue::String("<hi&>".into()));
    }

    #[test]
    fn pwsh_escape_decode() {
        let got = parse_clixml("<S>ab_x0001_cd</S>").unwrap();
        assert_eq!(got[0], PsValue::String("ab\u{0001}cd".into()));
    }

    /// Issue #18: PowerShell writes a character outside the BMP as the
    /// escapes of its two UTF-16 surrogates (`EncodeString`,
    /// serialization.cs), so 😀 arrives as `_xD83D__xDE00_`.
    #[test]
    fn surrogate_pair_escapes_decode_to_one_char() {
        let mut failures = Vec::new();
        for (escaped, expected) in [
            ("_xD83D__xDE00_", "\u{1F600}"),
            ("a_xD83D__xDE00_b", "a\u{1F600}b"),
            ("_xd83d__xde00_", "\u{1F600}"),
            ("_xD83D__xde00_", "\u{1F600}"),
            ("_xD83D__xDE00__xD83D__xDE01_", "\u{1F600}\u{1F601}"),
            ("_xD800__xDC00_", "\u{10000}"),
            ("_xDBFF__xDFFF_", "\u{10FFFF}"),
            // A lone surrogate: .NET would yield the bare code unit, which
            // a Rust `String` cannot hold, so it becomes U+FFFD.
            ("_xD83D_", "\u{FFFD}"),
            ("a_xD83D_b", "a\u{FFFD}b"),
            ("_xDE00_", "\u{FFFD}"),
            ("_xDE00__xD83D_", "\u{FFFD}\u{FFFD}"),
            ("_xD83D_x_xDE00_", "\u{FFFD}x\u{FFFD}"),
            ("_xD83D__x0041_", "\u{FFFD}A"),
            ("_xD83D__xD83D__xDE00_", "\u{FFFD}\u{1F600}"),
            ("_xD83D_xDE00_", "\u{FFFD}xDE00_"),
            // Unchanged around them.
            ("_x0041__x0042_", "AB"),
            // Deliberately preserves an existing quirk (`from_str_radix`
            // accepts a leading `+`; see the "Related" note of #18), so
            // that a future fix has to change this test on purpose.
            ("_x+041_", "A"),
            ("_X0041_", "_X0041_"),
        ] {
            let got = decode_pwsh_escapes(escaped);
            if got != expected {
                failures.push(format!("{escaped:?} -> {got:?}, expected {expected:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn surrogate_pair_escapes_decode_in_text_and_property_names() {
        let xml = r#"<Obj RefId="0"><MS><S N="k_xD83D__xDE00_">x_xD83D__xDE00_y</S><S N="_xDE00_">_xD83D_</S></MS></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        let expected = PsValue::Object(
            PsObject::new()
                .with("k\u{1F600}", PsValue::String("x\u{1F600}y".into()))
                .with("\u{FFFD}", PsValue::String("\u{FFFD}".into())),
        );
        assert_eq!(got, vec![expected]);
    }

    /// The encoder writes non-BMP characters as literal UTF-8, and escapes
    /// a literal `_x`, so they still come back exactly.
    #[test]
    fn non_bmp_characters_round_trip() {
        for text in [
            "\u{1F600}",
            "a\u{1F600}b\u{10000}\u{10FFFF}",
            "\u{1F600}_xD83D_",
            "_xD83D__xDE00_",
            "\u{FFFD}",
        ] {
            let value = PsValue::Object(PsObject::new().with(text, PsValue::String(text.into())));
            let xml = to_clixml(&value);
            assert_eq!(
                parse_clixml(&xml).unwrap(),
                vec![value],
                "{text:?} via {xml}"
            );
        }
    }

    #[test]
    fn object_with_member_set() {
        let xml = r#"<Obj RefId="0"><TN RefId="0"><T>System.Diagnostics.Process</T></TN><MS><S N="Name">svchost</S><I32 N="Id">42</I32><Nil N="Maybe"/></MS></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 1);
        let obj = match &got[0] {
            PsValue::Object(o) => o,
            _ => panic!("expected object"),
        };
        assert_eq!(
            obj.type_names,
            vec!["System.Diagnostics.Process".to_string()]
        );
        assert_eq!(obj.get("Name"), Some(&PsValue::String("svchost".into())));
        assert_eq!(obj.get("Id"), Some(&PsValue::I32(42)));
        assert_eq!(obj.get("Maybe"), Some(&PsValue::Null));
    }

    #[test]
    fn object_with_list_and_dict() {
        let xml = r#"<Obj RefId="0"><LST><I32>1</I32><I32>2</I32></LST></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        let obj = match &got[0] {
            PsValue::Object(o) => o,
            _ => panic!("expected object"),
        };
        assert_eq!(
            obj.get("_value"),
            Some(&PsValue::List(vec![PsValue::I32(1), PsValue::I32(2)]))
        );
    }

    #[test]
    fn tnref_resolution() {
        // Outer object defines TN with RefId=0. Inner object references it via TNRef.
        let xml = r#"
          <Obj RefId="0"><TN RefId="0"><T>Foo</T></TN><MS><S N="k">v</S></MS></Obj>
          <Obj RefId="1"><TNRef RefId="0"/><MS><I32 N="n">7</I32></MS></Obj>
        "#;
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 2);
        if let PsValue::Object(o) = &got[1] {
            assert_eq!(o.type_names, vec!["Foo".to_string()]);
            assert_eq!(o.get("n"), Some(&PsValue::I32(7)));
        } else {
            panic!();
        }
    }

    #[test]
    fn ref_resolution() {
        let xml = r#"<Obj RefId="abc"><MS><S N="k">v</S></MS></Obj><Ref RefId="abc"/>"#;
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], got[1]);
    }

    #[test]
    fn dangling_ref_becomes_null() {
        let got = parse_clixml(r#"<Ref RefId="missing"/>"#).unwrap();
        assert_eq!(got[0], PsValue::Null);
    }

    #[test]
    fn unknown_elements_are_skipped() {
        let xml =
            r#"<Obj RefId="0"><UnknownThing><nested/></UnknownThing><MS><S N="k">v</S></MS></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[0] {
            assert_eq!(o.get("k"), Some(&PsValue::String("v".into())));
        } else {
            panic!();
        }
    }

    #[test]
    fn roundtrip_complex_object() {
        let obj = PsObject {
            type_names: vec!["Foo".into(), "Bar".into()],
            to_string: None,
            properties: {
                let mut p = indexmap::IndexMap::new();
                p.insert("name".into(), PsValue::String("n".into()));
                p.insert("count".into(), PsValue::I32(3));
                p.insert("flag".into(), PsValue::Bool(true));
                p.insert("empty".into(), PsValue::Null);
                p.insert(
                    "tags".into(),
                    PsValue::List(vec![
                        PsValue::String("a".into()),
                        PsValue::String("b".into()),
                    ]),
                );
                p
            },
        };
        let xml = to_clixml(&PsValue::Object(obj.clone()));
        let got = parse_clixml(&xml).unwrap();
        let got_obj = match &got[0] {
            PsValue::Object(o) => o,
            _ => panic!(),
        };
        assert_eq!(got_obj.type_names, obj.type_names);
        assert_eq!(got_obj.get("name"), obj.properties.get("name"));
        assert_eq!(got_obj.get("count"), obj.properties.get("count"));
        assert_eq!(got_obj.get("flag"), obj.properties.get("flag"));
        assert_eq!(got_obj.get("empty"), Some(&PsValue::Null));
        // Embedded list comes back as an object whose _value is the list.
        if let Some(PsValue::Object(tags_obj)) = got_obj.get("tags") {
            assert_eq!(
                tags_obj.get("_value"),
                Some(&PsValue::List(vec![
                    PsValue::String("a".into()),
                    PsValue::String("b".into())
                ]))
            );
        } else {
            panic!("expected tags to be an object wrapping a list");
        }
    }

    #[test]
    fn cdata_section_decoded() {
        let got = parse_clixml("<S><![CDATA[hello & <world>]]></S>").unwrap();
        assert_eq!(got[0], PsValue::String("hello & <world>".into()));
    }

    #[test]
    fn top_level_ref_with_content_resolves() {
        // Non-self-closing `<Ref RefId="..">…</Ref>` at top level.
        let xml = r#"<Obj RefId="a"><MS><S N="k">v</S></MS></Obj><Ref RefId="a">ignored</Ref>"#;
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], got[1]);
    }

    #[test]
    fn empty_obj_body_produces_empty_object() {
        let got = parse_clixml("<Obj RefId=\"0\"></Obj>").unwrap();
        if let PsValue::Object(o) = &got[0] {
            assert!(o.properties.is_empty());
            assert!(o.type_names.is_empty(), "{:?}", o.type_names);
        } else {
            panic!();
        }
    }

    #[test]
    fn props_element_is_treated_like_ms() {
        let xml = r#"<Obj RefId="0"><Props><S N="k">v</S></Props></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[0] {
            assert_eq!(o.get("k"), Some(&PsValue::String("v".into())));
        } else {
            panic!();
        }
    }

    #[test]
    fn pwsh_escape_roundtrip() {
        assert_eq!(decode_pwsh_escapes("_x0041_BC"), "ABC");
        assert_eq!(decode_pwsh_escapes("no escapes here"), "no escapes here");
        assert_eq!(
            decode_pwsh_escapes("_xZZZZ_"),
            "_xZZZZ_",
            "invalid hex passes through"
        );
        assert_eq!(
            decode_pwsh_escapes("café"),
            "café",
            "multi-byte chars preserved"
        );
    }

    #[test]
    fn extended_primitives() {
        // SB (i8), By (u8), I16, U16, U32, U64
        let cases: Vec<(&str, PsValue)> = vec![
            ("<SB>-128</SB>", PsValue::I8(-128)),
            ("<By>255</By>", PsValue::U8(255)),
            ("<I16>-32000</I16>", PsValue::I16(-32000)),
            ("<U16>65535</U16>", PsValue::U16(65535)),
            ("<U32>4000000000</U32>", PsValue::U32(4_000_000_000)),
            ("<U64>18446744073709551615</U64>", PsValue::U64(u64::MAX)),
        ];
        for (xml, expected) in cases {
            let got = parse_clixml(xml).unwrap();
            assert_eq!(got.len(), 1, "{xml}");
            assert_eq!(got[0], expected, "{xml}");
        }
    }

    #[test]
    fn extended_primitive_errors() {
        assert!(parse_clixml("<SB>not_int</SB>").is_err());
        assert!(parse_clixml("<By>-1</By>").is_err());
        assert!(parse_clixml("<I16>99999</I16>").is_err());
        assert!(parse_clixml("<U16>-1</U16>").is_err());
        assert!(parse_clixml("<U32>-1</U32>").is_err());
        assert!(parse_clixml("<U64>not_a_number</U64>").is_err());
    }

    #[test]
    fn char_primitive() {
        let got = parse_clixml("<C>65</C>").unwrap();
        assert_eq!(got[0], PsValue::Char('A'));
    }

    #[test]
    fn char_invalid_code_point() {
        // Not a number
        assert!(parse_clixml("<C>abc</C>").is_err());
        assert!(parse_clixml("<C>-1</C>").is_err());
        assert!(parse_clixml("<C>4294967296</C>").is_err());
    }

    /// Older psrp-rs wrote `'😀'` as `<C>128512</C>`; it is still read back as
    /// that character, and a number that is no scalar value is U+FFFD.
    #[test]
    fn char_above_the_bmp_is_still_read_leniently() {
        assert_eq!(
            parse_clixml("<C>65536</C><C>128512</C><C>1114111</C><C>1114112</C><C>4294967295</C>")
                .unwrap(),
            vec![
                PsValue::Char('\u{10000}'),
                PsValue::Char('\u{1F600}'),
                PsValue::Char('\u{10FFFF}'),
                PsValue::Char('\u{FFFD}'),
                PsValue::Char('\u{FFFD}'),
            ]
        );
    }

    /// `"😀".ToCharArray()` is `<C>55357</C><C>56832</C>`: a lone surrogate
    /// is U+FFFD, wherever it sits, and does not cost the rest of the
    /// document (the whole `run` used to fail on it).
    #[test]
    fn char_surrogate_is_replacement_not_an_error() {
        for unit in [0xD800u32, 0xD83D, 0xDE00, 0xDFFF] {
            assert_eq!(
                parse_clixml(&format!("<C>{unit}</C>")).unwrap(),
                vec![PsValue::Char('\u{FFFD}')],
                "{unit:#x}"
            );
        }
        // The edges of the range are still real characters.
        assert_eq!(
            parse_clixml("<C>55295</C><C>57344</C><C>65535</C>").unwrap(),
            vec![
                PsValue::Char('\u{D7FF}'),
                PsValue::Char('\u{E000}'),
                PsValue::Char('\u{FFFF}'),
            ]
        );
        let got =
            parse_clixml(r#"<Obj RefId="0"><LST><C>55357</C><I32>2</I32><C>56832</C></LST></Obj>"#)
                .unwrap();
        let [PsValue::Object(o)] = got.as_slice() else {
            panic!("expected one object, got {got:?}");
        };
        assert_eq!(
            o.get("_value"),
            Some(&PsValue::List(vec![
                PsValue::Char('\u{FFFD}'),
                PsValue::I32(2),
                PsValue::Char('\u{FFFD}'),
            ]))
        );
    }

    #[test]
    fn base64_primitive() {
        // "aGVsbG8=" = "hello"
        let got = parse_clixml("<BA>aGVsbG8=</BA>").unwrap();
        assert_eq!(got[0], PsValue::Bytes(b"hello".to_vec()));
    }

    #[test]
    fn base64_invalid() {
        assert!(parse_clixml("<BA>!!!not-base64!!!</BA>").is_err());
    }

    #[test]
    fn guid_primitive() {
        let got = parse_clixml("<G>12345678-1234-1234-1234-123456789abc</G>").unwrap();
        if let PsValue::Guid(g) = &got[0] {
            assert_eq!(g.to_string(), "12345678-1234-1234-1234-123456789abc");
        } else {
            panic!("expected Guid");
        }
    }

    #[test]
    fn guid_invalid() {
        assert!(parse_clixml("<G>not-a-guid</G>").is_err());
    }

    #[test]
    fn datetime_and_duration() {
        let got = parse_clixml("<DT>2024-01-01T00:00:00Z</DT>").unwrap();
        assert_eq!(
            got[0],
            PsValue::DateTime("2024-01-01T00:00:00Z".to_string())
        );
        let got = parse_clixml("<TS>P1DT2H</TS>").unwrap();
        assert_eq!(got[0], PsValue::Duration("P1DT2H".to_string()));
    }

    #[test]
    fn version_uri_xml_scriptblock_securestring() {
        let cases = vec![
            ("<Version>5.1</Version>", PsValue::Version("5.1".into())),
            (
                "<URI>http://example.com</URI>",
                PsValue::Uri("http://example.com".into()),
            ),
            (
                "<XD>some xml data</XD>",
                PsValue::Xml("some xml data".into()),
            ),
            (
                "<SBK>Get-Process</SBK>",
                PsValue::ScriptBlock("Get-Process".into()),
            ),
            // `SCT` is not a PowerShell tag; it is only what psrp-rs
            // itself used to write, kept so that output still decodes.
            (
                "<SCT>Get-Process</SCT>",
                PsValue::ScriptBlock("Get-Process".into()),
            ),
            (
                "<SS>encrypted</SS>",
                PsValue::SecureString("encrypted".into()),
            ),
        ];
        for (xml, expected) in cases {
            let got = parse_clixml(xml).unwrap();
            assert_eq!(got.len(), 1, "{xml}");
            assert_eq!(got[0], expected, "{xml}");
        }
    }

    /// Regression (#19): PowerShell's script-block tag is `SBK`
    /// (`SerializationStrings.ScriptBlockTag`, MS-PSRP 2.2.5.1.23), and
    /// the decoder only knew `SCT`, so every `<SBK>` was skipped as an
    /// unknown element: a top-level output vanished, a property went
    /// missing, a list item disappeared and shifted the ones after it.
    ///
    /// The documents are verbatim `PSSerializer.Serialize` output
    /// (pwsh 7.3.12), indentation removed.
    #[test]
    fn script_block_sbk_from_powershell_is_not_dropped() {
        // Top level: `{}` and a body with XML metacharacters and a
        // literal `_x000D_`, which PowerShell escapes as in `<S>`.
        let got =
            parse_clixml(r#"<SBK></SBK><SBK> Get-Date "a&amp;b&lt;c&gt;" _x005F_x000D_ </SBK>"#)
                .unwrap();
        assert_eq!(
            got,
            vec![
                PsValue::ScriptBlock(String::new()),
                PsValue::ScriptBlock(r#" Get-Date "a&b<c>" _x000D_ "#.into()),
            ]
        );

        // `[pscustomobject]@{ Action = { 1 }; L = @({ 2 }, 3) }`: a
        // property value and a list item.
        let xml = concat!(
            r#"<Obj RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T>"#,
            r#"<T>System.Object</T></TN><MS><SBK N="Action"> 1 </SBK>"#,
            r#"<Obj N="L" RefId="1"><TN RefId="1"><T>System.Object[]</T><T>System.Array</T>"#,
            r#"<T>System.Object</T></TN><LST><SBK> 2 </SBK><I32>3</I32></LST></Obj></MS></Obj>"#,
        );
        let got = parse_clixml(xml).unwrap();
        let PsValue::Object(obj) = &got[0] else {
            panic!("expected an object, got {got:?}");
        };
        assert_eq!(obj.get("Action"), Some(&PsValue::ScriptBlock(" 1 ".into())));
        let Some(PsValue::Object(list)) = obj.get("L") else {
            panic!("expected `L` to be an object, got {obj:?}");
        };
        assert_eq!(
            list.get("_value"),
            Some(&PsValue::List(vec![
                PsValue::ScriptBlock(" 2 ".into()),
                PsValue::I32(3),
            ]))
        );
    }

    /// A script block survives the encoder and decoder at every position,
    /// with content that needs each kind of escape: XML metacharacters, a
    /// CR (which XML end-of-line handling would turn into LF) and a
    /// literal `_x` that would otherwise read as a `_xHHHH_` escape.
    #[test]
    fn script_block_round_trips_with_escapes() {
        let body = "if ($a -lt 1) {\r\n  'a&b' <c> \"_x000D_\" _x\r}\n";
        let sb = PsValue::ScriptBlock(body.into());

        let xml = to_clixml(&sb);
        assert!(xml.starts_with("<SBK>") && xml.ends_with("</SBK>"), "{xml}");
        assert!(!xml.contains('\r'), "literal CR in {xml:?}");
        assert_eq!(parse_clixml(&xml).unwrap(), vec![sb.clone()], "{xml}");

        let obj = PsValue::Object(PsObject::new().with("Action", sb.clone()));
        let xml = to_clixml(&obj);
        assert!(xml.contains(r#"<SBK N="Action">"#), "{xml}");
        assert_eq!(parse_clixml(&xml).unwrap(), vec![obj], "{xml}");

        let list = PsValue::List(vec![sb.clone(), PsValue::I32(3)]);
        let got = parse_clixml(&to_clixml(&list)).unwrap();
        let PsValue::Object(o) = &got[0] else {
            panic!("expected the list wrapped in an object, got {got:?}");
        };
        assert_eq!(o.get("_value"), Some(&list));

        // As a dict value and as a dict key.
        let dict = PsValue::Dict(vec![
            (PsValue::String("k".into()), sb.clone()),
            (sb.clone(), PsValue::I32(4)),
        ]);
        let xml = to_clixml(&dict);
        assert!(
            xml.contains(r#"<SBK N="Value">"#) && xml.contains(r#"<SBK N="Key">"#),
            "{xml}"
        );
        let got = parse_clixml(&xml).unwrap();
        let PsValue::Object(o) = &got[0] else {
            panic!("expected the dict wrapped in an object, got {got:?}");
        };
        assert_eq!(o.get("_value"), Some(&dict), "{xml}");
    }

    /// PowerShell normally writes an empty script block (or string) self-closed,
    /// `<SBK N="x" />`, and `<SBK></SBK>` only when its output buffer flushes
    /// before the end tag: neither may be dropped, wherever it appears (a
    /// self-closed `<S N="x"/>` in a member set or dict entry used to be lost).
    #[test]
    fn self_closed_script_block_is_an_empty_script_block() {
        let empty = PsValue::ScriptBlock(String::new());
        let wrapped = |xml: &str| -> PsValue {
            let got = parse_clixml(xml).unwrap();
            let [PsValue::Object(o)] = got.as_slice() else {
                panic!("expected one object, got {got:?}");
            };
            o.get("_value").cloned().unwrap_or(PsValue::Null)
        };

        // Top level, the legacy tag included.
        assert_eq!(
            parse_clixml("<SBK/><SCT/><I32>1</I32>").unwrap(),
            vec![empty.clone(), empty.clone(), PsValue::I32(1)]
        );
        // A list item: the items after it keep their position.
        assert_eq!(
            wrapped(r#"<Obj RefId="0"><LST><SBK/><I32>2</I32></LST></Obj>"#),
            PsValue::List(vec![empty.clone(), PsValue::I32(2)])
        );
        // A dict value and a dict key.
        assert_eq!(
            wrapped(concat!(
                r#"<Obj RefId="0"><DCT><En><S N="Key">k</S><SBK N="Value"/></En>"#,
                r#"<En><SBK N="Key"/><I32 N="Value">3</I32></En></DCT></Obj>"#,
            )),
            PsValue::Dict(vec![
                (PsValue::String("k".into()), empty.clone()),
                (empty.clone(), PsValue::I32(3)),
            ])
        );
        // A property. Member sets and dict entries now read every
        // self-closed value the way lists and the top level do, so a
        // self-closed `<S N="…"/>` is an empty string there too.
        let got = parse_clixml(
            r#"<Obj RefId="0"><MS><SBK N="Action"/><S N="Empty"/><I32 N="After">4</I32></MS></Obj>"#,
        )
        .unwrap();
        let [PsValue::Object(o)] = got.as_slice() else {
            panic!("expected one object, got {got:?}");
        };
        assert_eq!(o.get("Action"), Some(&empty));
        assert_eq!(o.get("Empty"), Some(&PsValue::String(String::new())));
        assert_eq!(o.get("After"), Some(&PsValue::I32(4)));
    }

    #[test]
    fn decimal_primitive() {
        let got = parse_clixml("<D>123.456</D>").unwrap();
        assert_eq!(got[0], PsValue::Decimal("123.456".to_string()));
    }

    #[test]
    fn single_float() {
        let got = parse_clixml("<Sg>1.5</Sg>").unwrap();
        if let PsValue::F32(v) = got[0] {
            assert!((v - 1.5).abs() < f32::EPSILON);
        } else {
            panic!("expected F32");
        }
    }

    #[test]
    fn single_float_special() {
        let got = parse_clixml("<Sg>NaN</Sg>").unwrap();
        assert!(matches!(got[0], PsValue::F32(v) if v.is_nan()));
        let got = parse_clixml("<Sg>Infinity</Sg>").unwrap();
        assert!(matches!(got[0], PsValue::F32(v) if v.is_infinite()));
    }

    #[test]
    fn single_float_error() {
        assert!(parse_clixml("<Sg>not-float</Sg>").is_err());
    }

    #[test]
    fn unknown_top_level_element_skipped() {
        let xml = "<FutureTag><nested>data</nested></FutureTag><I32>42</I32>";
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], PsValue::I32(42));
    }

    #[test]
    fn unknown_self_closing_element_skipped() {
        let xml = "<UnknownThing/><I32>7</I32>";
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], PsValue::I32(7));
    }

    #[test]
    fn empty_s_tag_self_closing() {
        let got = parse_clixml("<S/>").unwrap();
        assert_eq!(got[0], PsValue::String(String::new()));
    }

    #[test]
    fn eof_inside_obj_is_error() {
        assert!(parse_clixml("<Obj RefId=\"0\"><MS>").is_err());
    }

    #[test]
    fn eof_inside_list_is_error() {
        assert!(parse_clixml("<Obj RefId=\"0\"><LST><I32>1</I32>").is_err());
    }

    #[test]
    fn eof_inside_dict_is_error() {
        assert!(parse_clixml("<Obj RefId=\"0\"><DCT><En>").is_err());
    }

    #[test]
    fn eof_inside_text_is_error() {
        assert!(parse_clixml("<S>unclosed").is_err());
    }

    #[test]
    fn dict_entry_with_nil_key_and_value() {
        let xml = r#"<Obj RefId="0"><DCT><En><Nil N="Key"/><Nil N="Value"/></En></DCT></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[0] {
            if let Some(PsValue::Dict(entries)) = o.get("_value") {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0], (PsValue::Null, PsValue::Null));
            } else {
                panic!("expected dict");
            }
        } else {
            panic!("expected object");
        }
    }

    #[test]
    fn ref_inside_member_set() {
        let xml = r#"<Obj RefId="a"><MS><S N="k">v</S></MS></Obj><Obj RefId="b"><MS><Ref N="copy" RefId="a"/></MS></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[1] {
            assert_eq!(o.get("copy"), Some(&got[0]));
        } else {
            panic!();
        }
    }

    #[test]
    fn ie_que_stk_treated_as_list() {
        for tag in ["IE", "QUE", "STK"] {
            let xml = format!(r#"<Obj RefId="0"><{tag}><I32>1</I32><I32>2</I32></{tag}></Obj>"#);
            let got = parse_clixml(&xml).unwrap();
            if let PsValue::Object(o) = &got[0] {
                assert_eq!(
                    o.get("_value"),
                    Some(&PsValue::List(vec![PsValue::I32(1), PsValue::I32(2)])),
                    "{tag} should be treated as list"
                );
            } else {
                panic!("{tag} should produce object");
            }
        }
    }

    #[test]
    fn tnref_self_closing_in_obj() {
        let xml = r#"
          <Obj RefId="0"><TN RefId="0"><T>Foo</T></TN><MS><S N="k">v</S></MS></Obj>
          <Obj RefId="1"><TNRef RefId="0"/><MS><I32 N="n">7</I32></MS></Obj>
        "#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[1] {
            assert_eq!(o.type_names, vec!["Foo".to_string()]);
        } else {
            panic!();
        }
    }

    #[test]
    fn nil_inside_list() {
        let xml = r#"<Obj RefId="0"><LST><I32>1</I32><Nil/><I32>3</I32></LST></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[0] {
            assert_eq!(
                o.get("_value"),
                Some(&PsValue::List(vec![
                    PsValue::I32(1),
                    PsValue::Null,
                    PsValue::I32(3)
                ]))
            );
        } else {
            panic!();
        }
    }

    #[test]
    fn dict_roundtrip() {
        let v = PsValue::Dict(vec![
            (PsValue::String("k1".into()), PsValue::I32(1)),
            (PsValue::String("k2".into()), PsValue::String("v".into())),
        ]);
        let xml = to_clixml(&v);
        let got = parse_clixml(&xml).unwrap();
        if let PsValue::Object(o) = &got[0] {
            if let Some(PsValue::Dict(entries)) = o.get("_value") {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].0, PsValue::String("k1".into()));
                assert_eq!(entries[0].1, PsValue::I32(1));
            } else {
                panic!("dict lost");
            }
        } else {
            panic!();
        }
    }

    /// PowerShell writes the second occurrence of an object in one graph as a
    /// self-closed `<Ref RefId="…" />` (`WritePSObjectReference`): in a list
    /// item, a dict key or value, a property, or at the top level. It used to
    /// be dropped from a list (the items after it shifted) and read as `Null`
    /// in a dict entry.
    #[test]
    fn self_closed_ref_resolves_wherever_it_appears() {
        let o = |n: &str| {
            let mut obj = PsObject::default();
            obj.properties.insert("a".into(), PsValue::String(n.into()));
            PsValue::Object(obj)
        };
        let first = r#"<Obj RefId="1"><MS><S N="a">x</S></MS></Obj>"#;
        let decode = |xml: &str| {
            let got = parse_clixml(xml).unwrap();
            let [PsValue::Object(o)] = got.as_slice() else {
                panic!("expected one object, got {got:?}");
            };
            o.get("_value").cloned().unwrap_or(PsValue::Null)
        };

        // `@($o, $o, 3)`: the reference keeps its position.
        assert_eq!(
            decode(&format!(
                r#"<Obj RefId="0"><LST>{first}<Ref RefId="1" /><I32>3</I32></LST></Obj>"#
            )),
            PsValue::List(vec![o("x"), o("x"), PsValue::I32(3)])
        );
        // `@{a=$o; b=$o}`, and a reference used as a key.
        assert_eq!(
            decode(concat!(
                r#"<Obj RefId="0"><DCT>"#,
                r#"<En><S N="Key">a</S><Obj N="Value" RefId="1"><MS><S N="a">x</S></MS></Obj></En>"#,
                r#"<En><S N="Key">b</S><Ref N="Value" RefId="1" /></En>"#,
                r#"<En><Ref N="Key" RefId="1" /><I32 N="Value">9</I32></En>"#,
                r#"</DCT></Obj>"#,
            )),
            PsValue::Dict(vec![
                (PsValue::String("a".into()), o("x")),
                (PsValue::String("b".into()), o("x")),
                (o("x"), PsValue::I32(9)),
            ])
        );
        // A property, and the top level.
        let got = parse_clixml(&format!(
            r#"{first}<Obj RefId="2"><MS><Ref N="p" RefId="1" /></MS></Obj><Ref RefId="1" />"#
        ))
        .unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[2], o("x"));
        let PsValue::Object(holder) = &got[1] else {
            panic!("{got:?}");
        };
        assert_eq!(holder.get("p"), Some(&o("x")));
    }

    /// A reference to an id that is not decoded (dangling, or a cycle back to
    /// an object still being built) is `Null`, in a list as at the top level,
    /// and does not shift its neighbours.
    #[test]
    fn dangling_or_cyclic_ref_is_null_in_place() {
        assert_eq!(
            decode_value(
                r#"<Obj RefId="0"><LST><Ref RefId="nope" /><I32>2</I32><Ref RefId="0" /></LST></Obj>"#
            ),
            PsValue::List(vec![PsValue::Null, PsValue::I32(2), PsValue::Null])
        );
        // No RefId at all.
        assert_eq!(
            decode_value(r#"<Obj RefId="0"><LST><Ref /><I32>2</I32></LST></Obj>"#),
            PsValue::List(vec![PsValue::Null, PsValue::I32(2)])
        );
    }

    fn decode_value(xml: &str) -> PsValue {
        let got = parse_clixml(xml).unwrap();
        let [PsValue::Object(o)] = got.as_slice() else {
            panic!("expected one object, got {got:?}");
        };
        o.get("_value").cloned().unwrap_or(PsValue::Null)
    }

    /// A server can chain objects that each hold two references to the
    /// previous one: a few KiB of XML then expands to 2^n values. That used to
    /// exhaust the memory and abort the process; now it is a parse error.
    #[test]
    fn doubling_refs_are_a_bounded_error_not_an_oom() {
        let mut xml = String::from(r#"<Obj RefId="0"><LST><S>x</S></LST></Obj>"#);
        for k in 1..=40 {
            xml.push_str(&format!(
                r#"<Obj RefId="{k}"><LST><Ref RefId="{p}" /><Ref RefId="{p}" /></LST></Obj>"#,
                p = k - 1
            ));
        }
        let err = parse_clixml(&xml).expect_err("2^40 values must not decode");
        assert!(err.to_string().contains("expansion"), "{err}");
    }

    /// Chaining one reference per level also builds a value deeper than the
    /// parser itself would accept; it is refused the same way.
    #[test]
    fn chained_refs_cannot_outgrow_the_nesting_limit() {
        let mut xml = String::from(r#"<Obj RefId="0"><LST><S>x</S></LST></Obj>"#);
        for k in 1..=200 {
            xml.push_str(&format!(
                r#"<Obj RefId="{k}"><LST><Ref RefId="{p}" /></LST></Obj>"#,
                p = k - 1
            ));
        }
        let err = parse_clixml(&xml).expect_err("a 400-level value must not decode");
        assert!(err.to_string().contains("deeper"), "{err}");
    }

    /// Ordinary sharing stays far below both limits.
    #[test]
    fn ordinary_sharing_is_not_limited() {
        let mut xml = String::from(
            r#"<Obj RefId="0"><MS><S N="Name">svchost</S><I32 N="Id">42</I32></MS></Obj><Obj RefId="1"><LST>"#,
        );
        for _ in 0..1000 {
            xml.push_str(r#"<Ref RefId="0" />"#);
        }
        xml.push_str("</LST></Obj>");
        let got = parse_clixml(&xml).unwrap();
        let PsValue::Object(list) = &got[1] else {
            panic!("{got:?}");
        };
        let Some(PsValue::List(items)) = list.get("_value") else {
            panic!("{list:?}");
        };
        assert_eq!(items.len(), 1000);
        assert!(items.iter().all(|i| *i == got[0]));
    }

    /// Legitimate sharing grows with the document: 15 000 elements that point
    /// at one 100-character object materialize ~1.6 M units of weight, past
    /// the floor of the budget but within what the document's size allows.
    #[test]
    fn sharing_scales_with_the_document() {
        let mut xml = format!(
            r#"<Obj RefId="s"><MS><S N="Name">{}</S></MS></Obj><Obj RefId="l"><LST>"#,
            "x".repeat(100)
        );
        for _ in 0..15_000 {
            xml.push_str(r#"<Ref RefId="s" />"#);
        }
        xml.push_str("</LST></Obj>");
        let got = parse_clixml(&xml).unwrap();
        let PsValue::Object(list) = &got[1] else {
            panic!("expected the list object");
        };
        let Some(PsValue::List(items)) = list.get("_value") else {
            panic!("{list:?}");
        };
        assert_eq!(items.len(), 15_000);
    }

    /// A .NET enum as `PSSerializer` writes it (captured from pwsh over
    /// WinRM): the number is a nameless child, which used to be dropped, so
    /// every enum came back as an empty object.
    #[test]
    fn enum_value_is_kept_under_value() {
        let xml = concat!(
            r#"<Obj RefId="0"><TN RefId="0"><T>System.IO.FileAttributes</T><T>System.Enum</T>"#,
            r#"<T>System.ValueType</T><T>System.Object</T></TN>"#,
            r#"<ToString>ReadOnly, Hidden</ToString><I32>3</I32></Obj>"#,
        );
        let got = parse_clixml(xml).unwrap();
        let [PsValue::Object(o)] = got.as_slice() else {
            panic!("expected one object, got {got:?}");
        };
        assert_eq!(o.get("_value"), Some(&PsValue::I32(3)));
        assert_eq!(o.type_names[0], "System.IO.FileAttributes");
        assert_eq!(o.type_names[1], "System.Enum");
    }

    /// Other underlying types, and an enum inside a property, a list and a
    /// dictionary value (`CommandOrigin` of an `InvocationInfo`).
    #[test]
    fn enum_value_survives_inside_containers() {
        let en = |n: &str, v: &str| {
            format!(
                r#"<Obj RefId="9"><TN RefId="9"><T>E</T><T>System.Enum</T></TN><ToString>x</ToString><{n}>{v}</{n}></Obj>"#
            )
        };
        let xml = format!(
            r#"<Obj RefId="0"><MS>{}</MS></Obj>"#,
            en("I32", "1").replace("<Obj ", r#"<Obj N="Origin" "#)
        );
        let got = parse_clixml(&xml).unwrap();
        let [PsValue::Object(o)] = got.as_slice() else {
            panic!("{got:?}");
        };
        let Some(PsValue::Object(origin)) = o.get("Origin") else {
            panic!("{o:?}");
        };
        assert_eq!(origin.get("_value"), Some(&PsValue::I32(1)));

        let xml = format!(
            r#"<Obj RefId="0"><LST>{}{}</LST></Obj>"#,
            en("By", "7"),
            en("I64", "9000000000")
        );
        let got = parse_clixml(&xml).unwrap();
        let [PsValue::Object(list)] = got.as_slice() else {
            panic!("{got:?}");
        };
        let Some(PsValue::List(items)) = list.get("_value") else {
            panic!("{list:?}");
        };
        let values: Vec<_> = items
            .iter()
            .map(|i| match i {
                PsValue::Object(o) => o.get("_value").cloned(),
                _ => None,
            })
            .collect();
        assert_eq!(
            values,
            vec![Some(PsValue::U8(7)), Some(PsValue::I64(9_000_000_000))]
        );
    }

    /// An object that has properties keeps them: the nameless child only
    /// fills `_value` when there is no member set (as for `<LST>`).
    #[test]
    fn a_member_set_wins_over_a_nameless_scalar() {
        let xml = r#"<Obj RefId="0"><MS><S N="a">x</S></MS><I32>5</I32></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        let [PsValue::Object(o)] = got.as_slice() else {
            panic!("{got:?}");
        };
        assert_eq!(o.get("a"), Some(&PsValue::String("x".into())));
        assert!(o.get("_value").is_none());
    }
}
