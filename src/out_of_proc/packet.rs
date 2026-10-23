//! OutOfProc packets: one XML element per line.
//!
//! [`Packet`] renders and parses the eight elements, [`parse_line`] turns one
//! received line into a packet, and [`LineSplitter`] cuts a byte stream into
//! lines. No I/O happens here.

use crate::clixml::encode::{base64_decode, base64_encode};
pub(crate) use crate::error::escape_remote_text;
#[cfg(test)]
use crate::error::rewrites_output;
use crate::error::{MAX_SERVER_MESSAGE_CHARS, PsrpError, Result};
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;
use uuid::Uuid;

/// Largest payload, in raw bytes, of one emitted `<Data>` line.
pub(crate) const MAX_DATA_PAYLOAD: usize = 32 * 1024;

/// Longest received line accepted, terminator excluded: 24 times the longest
/// legitimate line (one 32 KiB fragment plus its header, base64-encoded).
pub(crate) const MAX_LINE_BYTES: usize = 1 << 20;

/// Prefix of the line `pwsh` writes just before it dies on a protocol error.
pub(crate) const SERVER_ERROR_PREFIX: &str = "__NamedPipeError__:";

/// How much of an offending line an error message quotes, in characters.
const QUOTED_LINE_CHARS: usize = 80;

/// The `Stream` attribute of a `<Data>` element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stream {
    /// Ordinary PSRP traffic.
    Default,
    /// The answer to a host prompt.
    PromptResponse,
}

impl Stream {
    fn as_str(self) -> &'static str {
        match self {
            Self::Default => "Default",
            Self::PromptResponse => "PromptResponse",
        }
    }

    /// Case-insensitive, like the server's `Enum.Parse(.., ignoreCase: true)`.
    fn parse(s: &str) -> Option<Self> {
        [Self::Default, Self::PromptResponse]
            .into_iter()
            .find(|v| v.as_str().eq_ignore_ascii_case(s))
    }
}

/// One OutOfProc packet, that is one line of the protocol.
///
/// The `Uuid` is `Uuid::nil()` for the session (the runspace pool), else a
/// pipeline id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Packet {
    /// PSRP fragment bytes.
    Data {
        stream: Stream,
        guid: Uuid,
        payload: Vec<u8>,
    },
    DataAck(Uuid),
    Command(Uuid),
    CommandAck(Uuid),
    Signal(Uuid),
    SignalAck(Uuid),
    Close(Uuid),
    CloseAck(Uuid),
}

impl Packet {
    /// The line PowerShell's own writer produces for this packet, `\n`-terminated.
    pub(crate) fn to_line(&self) -> String {
        let (name, guid) = match self {
            Self::Data {
                stream,
                guid,
                payload,
            } => {
                return format!(
                    "<Data Stream='{}' PSGuid='{}'>{}</Data>\n",
                    stream.as_str(),
                    guid.hyphenated(),
                    base64_encode(payload)
                );
            }
            Self::DataAck(g) => ("DataAck", g),
            Self::Command(g) => ("Command", g),
            Self::CommandAck(g) => ("CommandAck", g),
            Self::Signal(g) => ("Signal", g),
            Self::SignalAck(g) => ("SignalAck", g),
            Self::Close(g) => ("Close", g),
            Self::CloseAck(g) => ("CloseAck", g),
        };
        format!("<{name} PSGuid='{}' />\n", guid.hyphenated())
    }
}

/// Parse one received line.
///
/// `Ok(None)` for a blank (empty or whitespace-only) line. `Err` for a
/// `__NamedPipeError__:` line and for anything that is not exactly one
/// well-formed packet.
pub(crate) fn parse_line(line: &str) -> Result<Option<Packet>> {
    if line.trim().is_empty() {
        return Ok(None);
    }
    if let Some(head) = line.get(..SERVER_ERROR_PREFIX.len())
        && head.eq_ignore_ascii_case(SERVER_ERROR_PREFIX)
    {
        let message = line.get(SERVER_ERROR_PREFIX.len()..).unwrap_or_default();
        return Err(PsrpError::protocol(format!(
            "PowerShell reported a protocol error: {}",
            escape_remote_text(message, MAX_SERVER_MESSAGE_CHARS)
        )));
    }
    parse_element(line.trim()).map(Some).map_err(|why| {
        PsrpError::protocol(format!("malformed OutOfProc line ({why}): {}", quote(line)))
    })
}

/// The first `QUOTED_LINE_CHARS` characters of `text`, escaped for a log message.
///
/// Everything remote-controlled that reaches an error message goes through here.
fn snippet(text: &str) -> String {
    let mut out: String = text
        .chars()
        .take(QUOTED_LINE_CHARS)
        .flat_map(char::escape_debug)
        .collect();
    if text.chars().nth(QUOTED_LINE_CHARS).is_some() {
        out.push('…');
    }
    out
}

fn quote(line: &str) -> String {
    format!("\"{}\"", snippet(line))
}

/// Enough bytes for `QUOTED_LINE_CHARS + 1` characters, so that [`snippet`]
/// still sees whether the text goes on.
const QUOTED_LINE_BYTES: usize = (QUOTED_LINE_CHARS + 1) * 4;

/// [`quote`] for bytes that may not be UTF-8: only a bounded prefix is
/// decoded, lossily.
pub(crate) fn quote_bytes(bytes: &[u8]) -> String {
    let head = bytes.get(..QUOTED_LINE_BYTES).unwrap_or(bytes);
    quote(&String::from_utf8_lossy(head))
}

/// Parse exactly one packet element, with nothing before or after it.
///
/// These lines are not CLIXML, so the "no hand-rolled XML outside `clixml/`"
/// invariant does not apply; `quick-xml` still does the tokenizing.
fn parse_element(line: &str) -> std::result::Result<Packet, String> {
    let mut reader = Reader::from_str(line);

    let packet = match next_event(&mut reader)? {
        Event::Start(start) => {
            if start.name().as_ref() != "Data" {
                return Err(format!(
                    "unexpected element <{}>",
                    snippet(start.name().as_ref())
                ));
            }
            let (stream, guid) = data_attributes(&start)?;
            let text = match next_event(&mut reader)? {
                Event::Text(text) => text.xml_content(XmlVersion::Implicit1_0).into_owned(),
                _ => return Err("<Data> without content".to_owned()),
            };
            match next_event(&mut reader)? {
                Event::End(end) if end.name().as_ref() == "Data" => {}
                _ => return Err("<Data> not closed right after its content".to_owned()),
            }
            let payload = base64_decode(&text).ok_or("invalid base64 in <Data>")?;
            if payload.is_empty() {
                return Err("empty <Data> content".to_owned());
            }
            Packet::Data {
                stream,
                guid,
                payload,
            }
        }
        Event::Empty(element) => {
            let make: fn(Uuid) -> Packet = match element.name().as_ref() {
                "DataAck" => Packet::DataAck,
                "Command" => Packet::Command,
                "CommandAck" => Packet::CommandAck,
                "Signal" => Packet::Signal,
                "SignalAck" => Packet::SignalAck,
                "Close" => Packet::Close,
                "CloseAck" => Packet::CloseAck,
                other => return Err(format!("unexpected element <{}/>", snippet(other))),
            };
            make(guid_attribute(&element)?)
        }
        _ => return Err("not a single packet element".to_owned()),
    };
    match next_event(&mut reader)? {
        Event::Eof => Ok(packet),
        _ => Err("content after the packet element".to_owned()),
    }
}

fn next_event<'a>(reader: &mut Reader<&'a [u8]>) -> std::result::Result<Event<'a>, String> {
    reader.read_event().map_err(|e| snippet(&e.to_string()))
}

/// The attributes of an element, as `(name, value)` pairs; `Err(expected)`
/// as soon as there are more than `max`.
///
/// Stops at the first attribute past `max`: a line may hold ~100k of them,
/// and this runs synchronously, out of reach of any timeout. quick-xml
/// rejects a duplicate name itself (its checks are on by default).
fn attributes(
    element: &BytesStart<'_>,
    max: usize,
    expected: &str,
) -> std::result::Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(max);
    for attr in element.attributes() {
        let attr = attr.map_err(|e| snippet(&e.to_string()))?;
        if out.len() >= max {
            return Err(expected.to_owned());
        }
        let name = attr.key.as_ref().to_owned();
        let value = attr
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|e| snippet(&e.to_string()))?
            .into_owned();
        out.push((name, value));
    }
    Ok(out)
}

fn parse_guid(value: &str) -> std::result::Result<Uuid, String> {
    Uuid::parse_str(value).map_err(|_| "invalid PSGuid".to_owned())
}

/// The sole `PSGuid` attribute of an `*Ack` / `Command` / `Signal` / `Close` element.
fn guid_attribute(element: &BytesStart<'_>) -> std::result::Result<Uuid, String> {
    const EXPECTED: &str = "expected exactly one attribute, PSGuid";
    match attributes(element, 1, EXPECTED)?.as_slice() {
        [(name, value)] if name == "PSGuid" => parse_guid(value),
        _ => Err(EXPECTED.to_owned()),
    }
}

/// The `Stream` and `PSGuid` attributes of a `<Data>` element, in either order.
fn data_attributes(element: &BytesStart<'_>) -> std::result::Result<(Stream, Uuid), String> {
    const EXPECTED: &str = "expected exactly the attributes Stream and PSGuid";
    match attributes(element, 2, EXPECTED)?.as_slice() {
        [(a, x), (b, y)] if a == "Stream" && b == "PSGuid" => {
            Ok((parse_stream(x)?, parse_guid(y)?))
        }
        [(a, x), (b, y)] if a == "PSGuid" && b == "Stream" => {
            Ok((parse_stream(y)?, parse_guid(x)?))
        }
        _ => Err(EXPECTED.to_owned()),
    }
}

fn parse_stream(value: &str) -> std::result::Result<Stream, String> {
    Stream::parse(value).ok_or_else(|| "unknown Stream".to_owned())
}

/// Cuts the server's byte stream into lines.
///
/// A line ends at `\n`, with one `\r` before it removed. A U+FEFF opening the
/// very first line is removed. A line longer than [`MAX_LINE_BYTES`] and
/// invalid UTF-8 are errors; after an error the splitter is not reusable.
pub(crate) struct LineSplitter {
    /// Bytes of the line being assembled.
    buf: Vec<u8>,
    /// Whether a first line was already completed, so a BOM is no longer expected.
    seen_first_line: bool,
}

impl LineSplitter {
    pub(crate) fn new() -> Self {
        Self {
            buf: Vec::new(),
            seen_first_line: false,
        }
    }

    /// Appends `bytes`; returns every line they complete, without its `\n`
    /// or `\r\n`, and the error that stopped the split, if any.
    ///
    /// The lines completed before an error are returned with it, in order:
    /// a `__NamedPipeError__:` line followed, in the same chunk, by a line
    /// that is not UTF-8 still reaches the caller.
    ///
    /// Linear in `bytes.len()`: only the new bytes are searched for `\n`,
    /// and the partial line kept from earlier pushes is never rescanned.
    pub(crate) fn push(&mut self, bytes: &[u8]) -> (Vec<String>, Option<PsrpError>) {
        let mut lines = Vec::new();
        let mut rest = bytes;
        loop {
            let mut parts = rest.splitn(2, |b| *b == b'\n');
            let head = parts.next().unwrap_or_default();
            let Some(tail) = parts.next() else {
                // No `\n` left: `head` (all of `rest`) continues the partial line.
                if self.buf.len().saturating_add(head.len()) > MAX_LINE_BYTES {
                    return (lines, Some(too_long()));
                }
                self.buf.extend_from_slice(head);
                return (lines, None);
            };
            let line = if self.buf.is_empty() {
                self.finish_line(head)
            } else if self.buf.len().saturating_add(head.len()) > MAX_LINE_BYTES {
                Err(too_long())
            } else {
                let mut whole = std::mem::take(&mut self.buf);
                whole.extend_from_slice(head);
                self.finish_line(&whole)
            };
            match line {
                Ok(line) => lines.push(line),
                Err(e) => return (lines, Some(e)),
            }
            rest = tail;
        }
    }

    /// Validate one complete line (its `\n` already removed) and turn it into a `String`.
    fn finish_line(&mut self, line: &[u8]) -> Result<String> {
        if line.len() > MAX_LINE_BYTES {
            return Err(too_long());
        }
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let text = std::str::from_utf8(line).map_err(|e| {
            PsrpError::protocol(format!(
                "OutOfProc line is not valid UTF-8 ({e}): {}",
                quote_bytes(line)
            ))
        })?;
        let text = if self.seen_first_line {
            text
        } else {
            text.strip_prefix('\u{FEFF}').unwrap_or(text)
        };
        self.seen_first_line = true;
        Ok(text.to_owned())
    }
}

fn too_long() -> PsrpError {
    PsrpError::protocol(format!("OutOfProc line exceeds {MAX_LINE_BYTES} bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    const G: &str = "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9";
    const NIL: &str = "00000000-0000-0000-0000-000000000000";

    fn g() -> Uuid {
        Uuid::parse_str(G).unwrap()
    }

    /// `LineSplitter::push` as a `Result`: the lines, or the error alone.
    fn push(s: &mut LineSplitter, bytes: &[u8]) -> Result<Vec<String>> {
        match s.push(bytes) {
            (lines, None) => Ok(lines),
            (_, Some(e)) => Err(e),
        }
    }

    #[test]
    fn packets_render_exactly_like_powershell() {
        let data = Packet::Data {
            stream: Stream::Default,
            guid: g(),
            payload: b"\x00\x01PSRP".to_vec(),
        };
        assert_eq!(
            data.to_line(),
            "<Data Stream='Default' PSGuid='0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9'>AAFQU1JQ</Data>\n"
        );
        let nil = Uuid::nil();
        for (packet, name) in [
            (Packet::DataAck(nil), "DataAck"),
            (Packet::Command(nil), "Command"),
            (Packet::CommandAck(nil), "CommandAck"),
            (Packet::Signal(nil), "Signal"),
            (Packet::SignalAck(nil), "SignalAck"),
            (Packet::Close(nil), "Close"),
            (Packet::CloseAck(nil), "CloseAck"),
        ] {
            assert_eq!(packet.to_line(), format!("<{name} PSGuid='{NIL}' />\n"));
        }
    }

    #[test]
    fn every_packet_parses_back() -> Result<()> {
        let id = g();
        let packets = [
            Packet::Data {
                stream: Stream::Default,
                guid: id,
                payload: b"\x00\x01PSRP".to_vec(),
            },
            Packet::Data {
                stream: Stream::PromptResponse,
                guid: id,
                payload: b"hello".to_vec(),
            },
            Packet::DataAck(id),
            Packet::Command(id),
            Packet::CommandAck(id),
            Packet::Signal(id),
            Packet::SignalAck(id),
            Packet::Close(id),
            Packet::CloseAck(id),
        ];
        for p in packets {
            let line = p.to_line();
            assert_eq!(parse_line(line.trim_end_matches('\n'))?, Some(p));
        }
        Ok(())
    }

    #[test]
    fn accepts_double_quotes_and_any_stream_case() -> Result<()> {
        assert_eq!(
            parse_line(&format!("<DataAck PSGuid=\"{G}\"/>"))?,
            Some(Packet::DataAck(g()))
        );
        let line = format!("<Data Stream='promptresponse' PSGuid='{G}'>AA==</Data>");
        assert_eq!(
            parse_line(&line)?,
            Some(Packet::Data {
                stream: Stream::PromptResponse,
                guid: g(),
                payload: vec![0],
            })
        );
        Ok(())
    }

    #[test]
    fn blank_lines_are_skipped() -> Result<()> {
        assert_eq!(parse_line("")?, None);
        assert_eq!(parse_line("  \t")?, None);
        Ok(())
    }

    #[test]
    fn server_error_line_becomes_an_error_with_its_message() {
        for prefix in [SERVER_ERROR_PREFIX, &SERVER_ERROR_PREFIX.to_lowercase()] {
            let line = format!("{prefix}An unknown element \"\" was received.");
            let err = parse_line(&line).unwrap_err();
            assert!(matches!(err, PsrpError::Protocol(_)));
            assert!(
                err.to_string()
                    .contains("An unknown element \"\" was received."),
                "{err}"
            );
        }
    }

    #[test]
    fn server_error_message_is_escaped_but_keeps_its_text_and_quotes() {
        let line = format!(
            "{SERVER_ERROR_PREFIX}bad\u{1b}[2J\r\u{7}x\u{202e}y\u{2066}z \"q\" 'a' \\ é\u{a0}:"
        );
        let msg = parse_line(&line).unwrap_err().to_string();
        assert!(
            msg.contains("bad\\u{1b}[2J\\r\\u{7}x\\u{202e}y\\u{2066}z \"q\" 'a' \\ é\u{a0}:"),
            "{msg}"
        );
        assert!(
            !msg.chars()
                .any(|c| c.is_control() || matches!(c, '\u{202e}' | '\u{2066}')),
            "{msg:?}"
        );
    }

    #[test]
    fn escape_remote_text_leaves_no_output_rewriting_character() {
        let risky: String = ('\u{0}'..='\u{9f}')
            .filter(|c| c.is_control())
            .chain(['\u{ad}', '\u{61c}', '\u{180e}', '\u{feff}'])
            .chain('\u{200b}'..='\u{200f}')
            .chain('\u{2028}'..='\u{202e}')
            .chain('\u{2060}'..='\u{206f}')
            .chain('\u{fff9}'..='\u{fffb}')
            .chain('\u{e0000}'..='\u{e007f}')
            .collect();
        let out = escape_remote_text(&risky, usize::MAX);
        assert!(!out.chars().any(rewrites_output), "{out:?}");
        assert_eq!(
            escape_remote_text("keep \"this\" 'as' \\ is: é", 100),
            "keep \"this\" 'as' \\ is: é"
        );
        assert_eq!(escape_remote_text("abcdef", 3), "abc…");
        assert_eq!(escape_remote_text("abc", 3), "abc");
    }

    #[test]
    fn server_error_message_is_truncated() {
        let line = format!("{SERVER_ERROR_PREFIX}{}", "m".repeat(5000));
        let msg = parse_line(&line).unwrap_err().to_string();
        assert!(msg.contains(&"m".repeat(1024)));
        assert!(!msg.contains(&"m".repeat(1025)));
    }

    #[test]
    fn rejects_what_powershell_would_reject() {
        let lines = [
            format!("<Data Stream='Default' PSGuid='{G}'></Data>"),
            format!("<Data Stream='Default' PSGuid='{G}' />"),
            format!("<Data PSGuid='{G}'>AA==</Data>"),
            format!("<Data Stream='Other' PSGuid='{G}'>AA==</Data>"),
            format!("<Data Stream='Default' PSGuid='{G}'>***</Data>"),
            "<DataAck />".to_owned(),
            format!("<DataAck PSGuid='{G}' Extra='1' />"),
            "<DataAck PSGuid='not-a-guid' />".to_owned(),
            format!("<Bogus PSGuid='{G}' />"),
            format!("<DataAck PSGuid='{G}' /><DataAck PSGuid='{G}' />"),
            format!("<DataAck PSGuid='{G}' />junk"),
            format!("<!-- c --><DataAck PSGuid='{G}' />"),
            "hello from .bashrc".to_owned(),
            // Extras beyond the brief: duplicate attributes, case-sensitive
            // names, other event kinds.
            format!("<DataAck PSGuid='{G}' PSGuid='{G}' />"),
            format!("<DataAck psguid='{G}' />"),
            format!("<Data stream='Default' PSGuid='{G}'>AA==</Data>"),
            format!("<Data Stream='Default' Stream='Default' PSGuid='{G}'>AA==</Data>"),
            format!("<Data Stream='Default' PSGuid='{G}'><![CDATA[AA==]]></Data>"),
            format!("<Data Stream='Default' PSGuid='{G}'>AA==</Data><!-- c -->"),
            format!("<?xml version='1.0'?><DataAck PSGuid='{G}' />"),
            format!("<DataAck PSGuid='{G}'>x</DataAck>"),
            format!("<DataAck PSGuid='{G}'"),
            format!("<Data Stream='Default' PSGuid='{G}'>AA==</Data"),
            format!("<Data Stream='Default' PSGuid='{G}'>AA==</Close>"),
        ];
        for line in lines {
            assert!(parse_line(&line).is_err(), "accepted: {line}");
        }
    }

    #[test]
    fn an_element_with_many_attributes_is_rejected_at_once() {
        // One maximal line holds ~100k attributes; collecting them all, with
        // a duplicate scan, was quadratic and synchronous (no timeout can
        // interrupt it).
        let mut attrs = String::new();
        for i in 0..100_000 {
            write!(attrs, " a{i}=''").unwrap();
        }
        let budget = std::time::Duration::from_secs(1);
        for line in [
            format!("<DataAck{attrs} />"),
            format!("<Data{attrs}>AA==</Data>"),
        ] {
            let start = std::time::Instant::now();
            let err = parse_line(&line).unwrap_err();
            let took = start.elapsed();
            assert!(took < budget, "took {took:?}");
            assert!(err.to_string().contains("expected exactly"), "{err}");
        }
    }

    #[test]
    fn duplicate_attributes_are_rejected_by_quick_xml() {
        for line in [
            format!("<Data PSGuid='{G}' PSGuid='{G}'>AA==</Data>"),
            format!("<Data Stream='Default' Stream='Default' PSGuid='{G}'>AA==</Data>"),
            format!("<DataAck PSGuid='{G}' PSGuid='{G}' />"),
        ] {
            let msg = parse_line(&line).unwrap_err().to_string();
            assert!(msg.contains("duplicated attribute"), "{msg}");
        }
    }

    #[test]
    fn error_quotes_the_offending_line_truncated() {
        let msg = parse_line(&"x".repeat(500)).unwrap_err().to_string();
        assert!(msg.contains(&"x".repeat(80)));
        assert!(!msg.contains(&"x".repeat(81)));
    }

    #[test]
    fn error_escapes_the_offending_line() {
        let msg = parse_line("bad\u{1b}[31m line").unwrap_err().to_string();
        assert!(msg.contains("\\u{1b}"), "{msg}");
        assert!(!msg.contains('\u{1b}'));
    }

    #[test]
    fn error_never_echoes_remote_names_untruncated_or_unescaped() {
        // Remote-controlled names: 500 chars with a control char in the middle.
        let name = format!("{}\u{7}{}", "x".repeat(250), "x".repeat(250));
        let lines = [
            format!("<{name} PSGuid='{G}' />"),
            format!("<{name} Stream='Default' PSGuid='{G}'>AA==</{name}>"),
            format!("<DataAck {name}='1' {name}='2' />"),
            format!("<DataAck {name}='1' />"),
            format!("<Data Stream='Default' PSGuid='{G}'>AA==</{name}>"),
            format!("<DataAck {name}"),
            format!("<DataAck PSGuid='{G}' {name}"),
        ];
        for line in lines {
            let msg = parse_line(&line).unwrap_err().to_string();
            assert!(!msg.contains(&"x".repeat(81)), "long echo: {msg}");
            assert!(!msg.chars().any(char::is_control), "raw control: {msg:?}");
        }
    }

    #[test]
    fn splitter_strips_crlf_and_lf() -> Result<()> {
        let mut s = LineSplitter::new();
        let lines = push(
            &mut s,
            format!("<CloseAck PSGuid='{NIL}' />\r\n<DataAck PSGuid='{NIL}' />\n").as_bytes(),
        )?;
        assert_eq!(
            lines,
            [
                format!("<CloseAck PSGuid='{NIL}' />"),
                format!("<DataAck PSGuid='{NIL}' />")
            ]
        );
        Ok(())
    }

    #[test]
    fn splitter_keeps_a_partial_line_until_its_newline() -> Result<()> {
        let mut s = LineSplitter::new();
        assert_eq!(push(&mut s, b"<DataAck")?, Vec::<String>::new());
        assert_eq!(
            push(&mut s, format!(" PSGuid='{NIL}' />\r").as_bytes())?,
            Vec::<String>::new()
        );
        assert_eq!(
            push(&mut s, b"\n")?,
            [format!("<DataAck PSGuid='{NIL}' />")]
        );
        Ok(())
    }

    #[test]
    fn splitter_is_independent_of_chunk_boundaries() -> Result<()> {
        let transcript = format!(
            "<DataAck PSGuid='{NIL}' />\r\n<Data Stream='Default' PSGuid='{G}'>AA==</Data>\r\n<CloseAck PSGuid='{NIL}' />\r\n"
        );
        let bytes = transcript.as_bytes();

        let mut whole = LineSplitter::new();
        let expected = push(&mut whole, bytes)?;
        assert_eq!(expected.len(), 3);

        let mut one_by_one = LineSplitter::new();
        let mut got = Vec::new();
        for b in bytes {
            got.extend(push(&mut one_by_one, std::slice::from_ref(b))?);
        }
        assert_eq!(got, expected);

        // Cut exactly between the first `\r` and its `\n`.
        let cr = bytes.iter().position(|b| *b == b'\r').unwrap();
        let (head, tail) = bytes.split_at(cr + 1);
        let mut split = LineSplitter::new();
        let mut got = push(&mut split, head)?;
        got.extend(push(&mut split, tail)?);
        assert_eq!(got, expected);
        Ok(())
    }

    #[test]
    fn splitter_rejects_an_overlong_line() -> Result<()> {
        let mut ok = LineSplitter::new();
        let mut bytes = vec![b'a'; MAX_LINE_BYTES];
        bytes.push(b'\n');
        assert_eq!(push(&mut ok, &bytes)?.len(), 1);

        let mut bad = LineSplitter::new();
        assert!(push(&mut bad, &vec![b'a'; MAX_LINE_BYTES + 1]).is_err());

        // Overlong even though its terminator arrived in the same push.
        let mut bad = LineSplitter::new();
        let mut bytes = vec![b'a'; MAX_LINE_BYTES + 1];
        bytes.push(b'\n');
        assert!(push(&mut bad, &bytes).is_err());
        Ok(())
    }

    #[test]
    fn splitter_cost_stays_linear_when_a_line_trickles_in_byte_by_byte() {
        // A hostile server may send one maximal line one byte per SSH packet;
        // rescanning the partial line on every push made that quadratic
        // (minutes of CPU). Linear, it takes milliseconds even in debug.
        let budget = std::time::Duration::from_secs(5);
        let start = std::time::Instant::now();
        let mut s = LineSplitter::new();
        for i in 0..MAX_LINE_BYTES {
            let lines = push(&mut s, b"a").unwrap();
            assert_eq!(lines, Vec::<String>::new());
            assert!(
                start.elapsed() < budget,
                "{i} one-byte pushes took over {budget:?}: the splitter is not linear"
            );
        }
        let lines = push(&mut s, b"\n").unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].len(), MAX_LINE_BYTES);
    }

    #[test]
    fn splitter_returns_the_lines_completed_before_an_error() {
        let mut s = LineSplitter::new();
        let (lines, error) = s.push(b"__NamedPipeError__:boom\r\n\xff\r\n<CloseAck");
        assert_eq!(lines, ["__NamedPipeError__:boom"]);
        assert!(matches!(error, Some(PsrpError::Protocol(_))), "{error:?}");

        let mut s = LineSplitter::new();
        let mut bytes = b"<DataAck/>\n".to_vec();
        bytes.extend(vec![b'a'; MAX_LINE_BYTES + 1]);
        let (lines, error) = s.push(&bytes);
        assert_eq!(lines, ["<DataAck/>"]);
        assert!(error.is_some());
    }

    #[test]
    fn invalid_utf8_error_quotes_the_line_escaped_and_truncated() {
        let mut s = LineSplitter::new();
        let msg = push(&mut s, b"bad \xff line\x1b[31m\r\n")
            .unwrap_err()
            .to_string();
        assert!(msg.contains("\"bad \u{FFFD} line\\u{1b}[31m\""), "{msg}");
        assert!(!msg.contains('\u{1b}'), "{msg:?}");

        let mut long = vec![b'x'; 500];
        long.extend_from_slice(b"\xff\n");
        let msg = push(&mut LineSplitter::new(), &long)
            .unwrap_err()
            .to_string();
        assert!(msg.contains(&format!("\"{}…\"", "x".repeat(80))), "{msg}");
        assert!(!msg.contains(&"x".repeat(81)), "{msg}");
    }

    #[test]
    fn splitter_rejects_invalid_utf8() {
        let mut s = LineSplitter::new();
        assert!(push(&mut s, b"\xff\xfe<x>\n").is_err());
    }

    #[test]
    fn splitter_strips_a_bom_on_the_first_line_only() -> Result<()> {
        let mut s = LineSplitter::new();
        let lines = push(
            &mut s,
            format!("\u{FEFF}<CloseAck PSGuid='{NIL}' />\r\n\u{FEFF}x\n").as_bytes(),
        )?;
        assert_eq!(
            lines,
            [
                format!("<CloseAck PSGuid='{NIL}' />"),
                "\u{FEFF}x".to_owned()
            ]
        );
        Ok(())
    }

    #[test]
    fn data_attributes_are_accepted_in_either_order() -> Result<()> {
        let expected = Some(Packet::Data {
            stream: Stream::PromptResponse,
            guid: g(),
            payload: vec![0],
        });
        for line in [
            format!("<Data Stream='PromptResponse' PSGuid='{G}'>AA==</Data>"),
            format!("<Data PSGuid='{G}' Stream='PromptResponse'>AA==</Data>"),
        ] {
            assert_eq!(parse_line(&line)?, expected, "{line}");
        }
        Ok(())
    }

    #[test]
    fn data_with_other_attribute_names_is_rejected_for_that_reason() {
        // A valid value under a wrong name must not be taken for the right
        // attribute, whichever position it is in.
        for line in [
            format!("<Data Foo='{G}' Stream='Default'>AA==</Data>"),
            format!("<Data Stream='Default' Foo='{G}'>AA==</Data>"),
            format!("<Data Foo='Default' Bar='{G}'>AA==</Data>"),
            format!("<Data Foo='{G}' Bar='Default'>AA==</Data>"),
            format!("<Data PSGuid='{G}' Foo='Default'>AA==</Data>"),
            "<Data Foo='Default' Stream='Default'>AA==</Data>".to_owned(),
        ] {
            let err = parse_line(&line).unwrap_err().to_string();
            assert!(
                err.contains("expected exactly the attributes Stream and PSGuid"),
                "{line}: {err}"
            );
        }
    }

    #[test]
    fn quote_bytes_quotes_exactly_the_first_80_characters_of_a_long_line() {
        // 4-byte characters are the worst case for the byte budget: 81 of
        // them must reach `snippet` so that it can see the line goes on.
        let long = "\u{1F600}".repeat(100);
        assert_eq!(
            quote_bytes(long.as_bytes()),
            format!("\"{}…\"", "\u{1F600}".repeat(QUOTED_LINE_CHARS))
        );
        // Exactly 80 characters: nothing is cut, so no ellipsis.
        let exact = "\u{1F600}".repeat(QUOTED_LINE_CHARS);
        assert_eq!(quote_bytes(exact.as_bytes()), format!("\"{exact}\""));
    }
}
