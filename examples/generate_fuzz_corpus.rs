//! Generate the seed corpus for `cargo fuzz`. Run with:
//!
//! ```bash
//! cargo run --example generate_fuzz_corpus
//! ```
//!
//! The output is written under `fuzz/corpus/<target>/<name>.bin`. Each
//! seed is constructed with the public crate API so the bytes stay
//! in sync with the wire format.

use std::fs;
use std::path::PathBuf;

use psrp_rs::clixml::{PsObject, PsValue, to_clixml};
use psrp_rs::fragment::{Fragment, encode_message};
use psrp_rs::message::{Destination, MessageType, PsrpMessage};

fn write(target: &str, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("fuzz");
    path.push("corpus");
    path.push(target);
    fs::create_dir_all(&path)?;
    path.push(name);
    fs::write(&path, bytes)?;
    println!("wrote {} bytes -> {}", bytes.len(), path.display());
    Ok(())
}

fn main() -> std::io::Result<()> {
    // ----- fragment_reassembler -----
    // Empty single-fragment message: header only, blob is empty.
    let empty = Fragment {
        object_id: 1,
        fragment_id: 0,
        start: true,
        end: true,
        blob: Vec::new(),
    }
    .encode();
    write("fragment_reassembler", "empty.bin", &empty)?;

    // Single small message in one fragment.
    let small = encode_message(2, b"hello world");
    write("fragment_reassembler", "single.bin", &small)?;

    // Two interleaved object ids — A is split across two fragments,
    // B is a single fragment squeezed in between.
    let a_payload = vec![0xAA; psrp_rs::fragment::MAX_FRAGMENT_PAYLOAD + 5];
    let b_payload = b"beta".to_vec();
    let a_frags = psrp_rs::fragment::split_message(100, &a_payload);
    let b_frags = psrp_rs::fragment::split_message(200, &b_payload);
    let mut interleaved = Vec::new();
    interleaved.extend(a_frags[0].encode());
    interleaved.extend(b_frags[0].encode());
    interleaved.extend(a_frags[1].encode());
    write("fragment_reassembler", "multi.bin", &interleaved)?;

    // ----- clixml_decoder -----
    write("clixml_decoder", "primitive.xml", b"<I32>42</I32>")?;
    write(
        "clixml_decoder",
        "obj_with_ms.xml",
        br#"<Obj RefId="0"><TN RefId="0"><T>System.Diagnostics.Process</T></TN><MS><S N="Name">svchost</S><I32 N="Id">42</I32><Nil N="Maybe"/></MS></Obj>"#,
    )?;
    write(
        "clixml_decoder",
        "ref.xml",
        br#"<Obj RefId="abc"><MS><S N="k">v</S></MS></Obj><Ref RefId="abc"/>"#,
    )?;
    let dt_obj = to_clixml(&PsValue::Object(
        PsObject::new()
            .with("Created", PsValue::DateTime("2024-01-01T00:00:00".into()))
            .with("Bytes", PsValue::Bytes(vec![1, 2, 3]))
            .with("Id", PsValue::Guid(uuid::Uuid::nil())),
    ));
    write("clixml_decoder", "extended_types.xml", dt_obj.as_bytes())?;

    // ----- message_decode -----
    let minimal = PsrpMessage {
        destination: Destination::Server,
        message_type: MessageType::SessionCapability,
        rpid: uuid::Uuid::nil(),
        pid: uuid::Uuid::nil(),
        data: String::new(),
    }
    .encode();
    write("message_decode", "minimal.bin", &minimal)?;

    let with_body = PsrpMessage {
        destination: Destination::Client,
        message_type: MessageType::PipelineOutput,
        rpid: uuid::Uuid::new_v4(),
        pid: uuid::Uuid::new_v4(),
        data: "<I32>1</I32>".into(),
    }
    .encode();
    write("message_decode", "pipeline_output.bin", &with_body)?;

    Ok(())
}
