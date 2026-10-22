//! OutOfProc packets: one XML element per line.
//!
//! [`Packet`] renders and parses the eight elements, [`parse_line`] turns one
//! received line into a packet, and [`LineSplitter`] cuts a byte stream into
//! lines. No I/O happens here.

use crate::clixml::encode::{base64_decode, base64_encode};
use crate::error::{PsrpError, Result};
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

/// How much of a `__NamedPipeError__:` message an error message quotes, in characters.
const QUOTED_SERVER_ERROR_CHARS: usize = 1024;

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
        let message: String = message.chars().take(QUOTED_SERVER_ERROR_CHARS).collect();
        return Err(PsrpError::protocol(format!(
            "PowerShell reported a protocol error: {message}"
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

/// The attributes of an element, as `(name, value)` pairs. Duplicates are an error.
fn attributes(element: &BytesStart<'_>) -> std::result::Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = Vec::new();
    for attr in element.attributes() {
        let attr = attr.map_err(|e| snippet(&e.to_string()))?;
        let name = attr.key.as_ref().to_owned();
        if out.iter().any(|(n, _)| *n == name) {
            return Err(format!("duplicate attribute {}", snippet(&name)));
        }
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
    match attributes(element)?.as_slice() {
        [(name, value)] if name == "PSGuid" => parse_guid(value),
        _ => Err("expected exactly one attribute, PSGuid".to_owned()),
    }
}

/// The `Stream` and `PSGuid` attributes of a `<Data>` element, in either order.
fn data_attributes(element: &BytesStart<'_>) -> std::result::Result<(Stream, Uuid), String> {
    match attributes(element)?.as_slice() {
        [(a, x), (b, y)] if a == "Stream" && b == "PSGuid" => {
            Ok((parse_stream(x)?, parse_guid(y)?))
        }
        [(a, x), (b, y)] if a == "PSGuid" && b == "Stream" => {
            Ok((parse_stream(y)?, parse_guid(x)?))
        }
        _ => Err("expected exactly the attributes Stream and PSGuid".to_owned()),
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

    /// Appends `bytes`; returns every completed line without its `\n` or `\r\n`.
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<Vec<String>> {
        let mut data = std::mem::take(&mut self.buf);
        data.extend_from_slice(bytes);

        let mut lines = Vec::new();
        let mut rest: &[u8] = &[];
        for segment in data.split_inclusive(|b| *b == b'\n') {
            match segment.strip_suffix(b"\n") {
                Some(line) => lines.push(self.finish_line(line)?),
                None => rest = segment,
            }
        }
        if rest.len() > MAX_LINE_BYTES {
            return Err(too_long());
        }
        self.buf = rest.to_vec();
        Ok(lines)
    }

    /// Validate one complete line (its `\n` already removed) and turn it into a `String`.
    fn finish_line(&mut self, line: &[u8]) -> Result<String> {
        if line.len() > MAX_LINE_BYTES {
            return Err(too_long());
        }
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let text = std::str::from_utf8(line)
            .map_err(|e| PsrpError::protocol(format!("OutOfProc line is not valid UTF-8: {e}")))?;
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

    const G: &str = "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9";
    const NIL: &str = "00000000-0000-0000-0000-000000000000";

    fn g() -> Uuid {
        Uuid::parse_str(G).unwrap()
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
        let lines = s.push(
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
        assert_eq!(s.push(b"<DataAck")?, Vec::<String>::new());
        assert_eq!(
            s.push(format!(" PSGuid='{NIL}' />\r").as_bytes())?,
            Vec::<String>::new()
        );
        assert_eq!(s.push(b"\n")?, [format!("<DataAck PSGuid='{NIL}' />")]);
        Ok(())
    }

    #[test]
    fn splitter_is_independent_of_chunk_boundaries() -> Result<()> {
        let transcript = format!(
            "<DataAck PSGuid='{NIL}' />\r\n<Data Stream='Default' PSGuid='{G}'>AA==</Data>\r\n<CloseAck PSGuid='{NIL}' />\r\n"
        );
        let bytes = transcript.as_bytes();

        let mut whole = LineSplitter::new();
        let expected = whole.push(bytes)?;
        assert_eq!(expected.len(), 3);

        let mut one_by_one = LineSplitter::new();
        let mut got = Vec::new();
        for b in bytes {
            got.extend(one_by_one.push(std::slice::from_ref(b))?);
        }
        assert_eq!(got, expected);

        // Cut exactly between the first `\r` and its `\n`.
        let cr = bytes.iter().position(|b| *b == b'\r').unwrap();
        let (head, tail) = bytes.split_at(cr + 1);
        let mut split = LineSplitter::new();
        let mut got = split.push(head)?;
        got.extend(split.push(tail)?);
        assert_eq!(got, expected);
        Ok(())
    }

    #[test]
    fn splitter_rejects_an_overlong_line() -> Result<()> {
        let mut ok = LineSplitter::new();
        let mut bytes = vec![b'a'; MAX_LINE_BYTES];
        bytes.push(b'\n');
        assert_eq!(ok.push(&bytes)?.len(), 1);

        let mut bad = LineSplitter::new();
        assert!(bad.push(&vec![b'a'; MAX_LINE_BYTES + 1]).is_err());

        // Overlong even though its terminator arrived in the same push.
        let mut bad = LineSplitter::new();
        let mut bytes = vec![b'a'; MAX_LINE_BYTES + 1];
        bytes.push(b'\n');
        assert!(bad.push(&bytes).is_err());
        Ok(())
    }

    #[test]
    fn splitter_rejects_invalid_utf8() {
        let mut s = LineSplitter::new();
        assert!(s.push(b"\xff\xfe<x>\n").is_err());
    }

    #[test]
    fn splitter_strips_a_bom_on_the_first_line_only() -> Result<()> {
        let mut s = LineSplitter::new();
        let lines =
            s.push(format!("\u{FEFF}<CloseAck PSGuid='{NIL}' />\r\n\u{FEFF}x\n").as_bytes())?;
        assert_eq!(
            lines,
            [
                format!("<CloseAck PSGuid='{NIL}' />"),
                "\u{FEFF}x".to_owned()
            ]
        );
        Ok(())
    }
}
