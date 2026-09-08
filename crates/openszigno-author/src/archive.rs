//! The single-member ZIP a `zip -> base64` document carries.
//!
//! The reader expects exactly one regular-file member whose name is a plain
//! basename, so that is what is written: one member, named after the
//! document, deflated, with a fixed modification time so the same input
//! always produces the same archive. The compression ratio the reader
//! enforces is checked here too, because a payload that compresses better
//! than the reader's ratio limit would produce a dossier nothing could
//! extract.

use std::io::{Cursor, Write};

use openszigno_core::Limits;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

use crate::error::{Error, ErrorCode};

/// Deflate `bytes` into a one-member ZIP archive named `name`.
///
/// `name` has already passed the title rules, so it is one safe basename.
pub fn compress(name: &str, bytes: &[u8], limits: &Limits) -> Result<Vec<u8>, Error> {
    let failed = || {
        Error::new(
            ErrorCode::ZipFailed,
            "the document could not be packed into a ZIP archive",
        )
    };
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        // Pinned, so that two runs over the same bytes agree. The value is
        // the ZIP epoch, which is what this crate uses without its optional
        // clock feature; setting it explicitly keeps the output stable even
        // if that feature is ever enabled elsewhere in the workspace.
        .last_modified_time(DateTime::default())
        .large_file(false);
    writer.start_file(name, options).map_err(|_| failed())?;
    writer.write_all(bytes).map_err(|_| failed())?;
    let archive = writer.finish().map_err(|_| failed())?.into_inner();

    check_ratio(&archive, bytes.len() as u64, limits)?;
    Ok(archive)
}

/// Refuse an archive the reader's compression-ratio limit would reject.
///
/// The compressed size is read back from the archive with the same reader the
/// extraction path uses, so the two see the same number.
fn check_ratio(archive: &[u8], expanded: u64, limits: &Limits) -> Result<(), Error> {
    let unreadable = || {
        Error::new(
            ErrorCode::ZipFailed,
            "the packed ZIP archive could not be read back",
        )
    };
    let mut reader = ZipArchive::new(Cursor::new(archive)).map_err(|_| unreadable())?;
    let compressed = reader
        .by_index(0)
        .map_err(|_| unreadable())?
        .compressed_size()
        .min(archive.len() as u64);
    if expanded > 0
        && (compressed == 0
            || expanded > compressed.saturating_mul(limits.max_zip_compression_ratio))
    {
        return Err(Error::new(
            ErrorCode::ZipRatioLimit,
            format!(
                "the document compresses better than the {}:1 ratio the reader accepts; \
                 store it without --zip",
                limits.max_zip_compression_ratio
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use openszigno_core::{DecodeOutcome, Limits};

    #[test]
    fn the_same_bytes_always_pack_to_the_same_archive() {
        let limits = Limits::default();
        let first = compress("hello.txt", b"hello from openSzigno\n", &limits).expect("packs");
        let second = compress("hello.txt", b"hello from openSzigno\n", &limits).expect("packs");
        assert_eq!(first, second);
    }

    #[test]
    fn the_archive_holds_one_member_under_the_given_name() {
        let archive = compress("note.txt", b"a short note\n", &Limits::default()).expect("packs");
        let mut reader = ZipArchive::new(Cursor::new(archive.as_slice())).expect("reads back");
        assert_eq!(reader.len(), 1);
        let member = reader.by_index(0).expect("one member");
        assert_eq!(member.name(), "note.txt");
        assert!(!member.is_dir());
    }

    #[test]
    fn a_payload_that_compresses_too_well_is_refused() {
        let limits = Limits::default();
        let error = compress("zeros.txt", &vec![b'0'; 64 * 1024], &limits)
            .expect_err("64 KiB of one byte beats a 100:1 ratio");
        assert_eq!(error.code(), ErrorCode::ZipRatioLimit);
        assert!(!error.message().contains("zeros.txt"));
    }

    /// The archive this crate writes is one the reader actually expands.
    #[test]
    fn the_reader_expands_what_this_writes() {
        let payload = b"round trip through zip and base64\n";
        let dossier = crate::build(
            &crate::DossierSpec {
                title: "Round trip".to_owned(),
                created: "2026-01-01T00:00:00Z".to_owned(),
                documents: vec![crate::DocumentSpec {
                    title: "round.txt".to_owned(),
                    media_type: None,
                    bytes: payload.to_vec(),
                    compress: true,
                }],
            },
            &Limits::default(),
        )
        .expect("builds");
        let parsed =
            openszigno_core::parse(&dossier.bytes, &Limits::default()).expect("parses back");
        let DecodeOutcome::Decoded(decoded) = parsed
            .decode_document(0, &Limits::default())
            .expect("decodes")
        else {
            panic!("the document must decode");
        };
        assert_eq!(decoded.bytes, payload);
    }
}
