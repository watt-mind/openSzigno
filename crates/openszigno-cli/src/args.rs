//! The command line itself: the `clap` types for every command, and the
//! shared plumbing that turns their common flags into parse options.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use openszigno_core::{KNOWN_COMPATIBLE_NAMESPACES, Limits, ParseOptions};
use openszigno_verify::{format_rfc3339, parse_rfc3339};

/// Nesting levels `--max-depth` can never exceed, whatever the caller asks
/// for. A flag must not be able to disable a bound.
pub(crate) const MAX_NESTING_DEPTH: u32 = 8;

#[derive(Debug, Parser)]
#[command(
    name = "openszigno",
    version,
    about = "Inspect, extract, and verify Microsec e-Szigno dossiers",
    long_about = "Inspect, extract, and verify Microsec e-Szigno dossiers. `verify` checks XMLDSig/XAdES signatures, certificate paths, and revocation against trust material you supply; it never judges legal authenticity."
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Identify a dossier and summarize its capabilities.
    Inspect(InputArgs),
    /// List documents and signature/timestamp presence.
    List(InputArgs),
    /// Extract supported document payloads without overwriting files.
    Extract(ExtractArgs),
    /// Apply strict structural checks (not cryptographic verification).
    ValidateStructure(InputArgs),
    /// Verify XMLDSig/XAdES signatures, certificate paths, and revocation.
    Verify(VerifyArgs),
    /// Build a new, unsigned dossier from files on disk.
    Create(CreateArgs),
    /// Print the agent skill (SKILL.md) that teaches an AI agent this CLI.
    Skill,
}

/// A validation time from `--at`, kept in both the shape the report needs and
/// the shape the clock needs.
#[derive(Clone, Debug)]
pub(crate) struct ValidationTime {
    pub(crate) text: String,
    pub(crate) unix: i64,
}

/// Parse `--at` during command-line parsing, so an unusable value is a usage
/// error (exit 2) rather than a half-run verification.
fn parse_validation_time(value: &str) -> Result<ValidationTime, String> {
    parse_rfc3339(value)
        .map(|unix| ValidationTime {
            text: value.to_owned(),
            unix,
        })
        .ok_or_else(|| "expected an RFC 3339 timestamp".to_owned())
}

#[derive(Clone, Debug, Args)]
pub(crate) struct VerifyArgs {
    /// Input .es3 dossier, or `-` to read it from standard input.
    pub(crate) file: PathBuf,
    /// Emit one stable JSON object on stdout.
    #[arg(long)]
    pub(crate) json: bool,
    /// Also accept a dossier whose root Dossier element is in this namespace,
    /// in addition to the known-compatible ones. Repeatable.
    #[arg(long = "allow-namespace", value_name = "URI")]
    pub(crate) allow_namespace: Vec<String>,
    /// Directory holding trust anchors (`anchors/`) and optional extra CA
    /// certificates (`intermediates/`), as PEM or DER. Without it every chain
    /// check is `unknown`.
    #[arg(long = "trust-store", value_name = "DIR")]
    pub(crate) trust_store: Option<PathBuf>,
    /// ETSI TS 119 612 trusted list to take trust anchors from, as XML.
    /// Repeatable. Its anchors join the `--trust-store` ones, each reported
    /// with its origin, and only these can make a chain `qualified`.
    #[arg(long = "trust-list", value_name = "FILE")]
    pub(crate) trust_list: Vec<PathBuf>,
    /// Certificate, PEM or DER, that must have signed every `--trust-list`.
    /// Obtain it out of band: for the EU list of trusted lists, from the
    /// Official Journal. Without it, and without `--lotl`, the lists are read
    /// but reported as unverified, which caps the verdict at `indeterminate`.
    #[arg(long = "trust-list-signer", value_name = "CERT")]
    pub(crate) trust_list_signer: Option<PathBuf>,
    /// EU list of trusted lists (XML). Its `PointersToOtherTSL` entries name
    /// the signing certificates of the national lists, so one out-of-band
    /// certificate — the LOTL's, passed as `--trust-list-signer` — bootstraps
    /// the verification of every `--trust-list`. The LOTL contributes no trust
    /// anchors of its own.
    #[arg(long = "lotl", value_name = "FILE")]
    pub(crate) lotl: Option<PathBuf>,
    /// Directory of CRLs (`crls/`) and OCSP responses (`ocsp/`) to check
    /// revocation against, in addition to the signature's own
    /// `xades:RevocationValues`. Nothing is ever fetched.
    #[arg(long = "revocation-store", value_name = "DIR")]
    pub(crate) revocation_store: Option<PathBuf>,
    /// Do not check revocation at all. Documented as producing at most
    /// `indeterminate`: a signature whose certificate might have been revoked
    /// is not one this tool will call valid.
    #[arg(long = "no-revocation", conflicts_with_all = ["online", "online_cache", "online_proxy", "online_allow_private"])]
    pub(crate) no_revocation: bool,
    /// Fetch revocation data the offline material does not cover, from the CRL
    /// distribution points and AIA OCSP responders the certificates themselves
    /// publish. This is the only thing that makes openszigno touch the
    /// network, and it never contacts a URL that did not come out of a
    /// certificate. Timeouts, size caps and a refusal to follow a redirect to
    /// another host are fixed; everything fetched is checked by exactly the
    /// same rules as offline material, so `--online` can only add data, never
    /// relax a rule.
    #[arg(long = "online")]
    pub(crate) online: bool,
    /// Write everything `--online` fetched into this directory, laid out like
    /// a `--revocation-store`, so a later offline run reproduces this result.
    #[arg(long = "online-cache", value_name = "DIR", requires = "online")]
    pub(crate) online_cache: Option<PathBuf>,
    /// Permit `--online` to contact loopback, private (RFC 1918), link-local
    /// and unique-local addresses, and the host name `localhost`. Refused by
    /// default: the URL comes out of a certificate the caller has not yet
    /// established trust in, so without this flag a dossier cannot point the
    /// verifier at a service on the machine or the network it runs on. Give it
    /// only for an internal CA that really does publish there.
    #[arg(long = "online-allow-private", requires = "online")]
    pub(crate) online_allow_private: bool,
    /// Route `--online` fetches through this proxy. Without it no proxy is
    /// used at all — in particular, none from `HTTP_PROXY` or its relatives,
    /// which are deliberately ignored.
    #[arg(long = "online-proxy", value_name = "URL", requires = "online")]
    pub(crate) online_proxy: Option<String>,
    /// Validation time as an RFC 3339 timestamp. Overrides everything: without
    /// it, a signature whose timestamp fully verified is validated at that
    /// token's genTime, and otherwise at the current time.
    #[arg(long, value_name = "TIME", value_parser = parse_validation_time)]
    pub(crate) at: Option<ValidationTime>,
    /// Admit SHA-1 digests and RSA-SHA1 signature methods for diagnosis only.
    /// The verdict is capped at `indeterminate` and no failed check can become
    /// a passed one. MD5, HMAC, DSA, and RSA keys below 2048 bits stay refused.
    #[arg(long = "allow-legacy-algorithms")]
    pub(crate) allow_legacy_algorithms: bool,
}

impl VerifyArgs {
    pub(crate) fn parse_options(&self) -> ParseOptions {
        parse_options(&self.allow_namespace)
    }
}

/// A creation date from `--created`, already normalised to the RFC 3339 UTC
/// seconds form the dossier is written with.
#[derive(Clone, Debug)]
pub(crate) struct CreationDate(pub(crate) String);

/// Parse `--created` during command-line parsing, so an unusable value is a
/// usage error (exit 2) rather than a half-written dossier.
fn parse_creation_date(value: &str) -> Result<CreationDate, String> {
    parse_rfc3339(value)
        .map(|unix| CreationDate(format_rfc3339(unix)))
        .ok_or_else(|| "expected an RFC 3339 timestamp".to_owned())
}

#[derive(Clone, Debug, Args)]
pub(crate) struct CreateArgs {
    /// The dossier to write. An existing file is never overwritten.
    #[arg(short, long, value_name = "FILE")]
    pub(crate) output: PathBuf,
    /// The dossier's own title.
    #[arg(long, value_name = "TITLE")]
    pub(crate) title: String,
    /// A document to place in the dossier, as `PATH`, `PATH::TITLE`, or
    /// `PATH::TITLE::TYPE/SUBTYPE`. The title defaults to the file's
    /// basename and the media type to the one registered for its extension.
    /// Repeatable; documents are written in the order given.
    #[arg(long = "document", value_name = "PATH[::TITLE[::MIME]]")]
    pub(crate) document: Vec<String>,
    /// Store every `--document` payload as `zip -> base64` instead of
    /// `base64`. Embedded dossiers are always stored as `base64`.
    #[arg(long)]
    pub(crate) zip: bool,
    /// An existing dossier to embed as one document. It is parsed first, and
    /// is titled `<stem>.dosszie` so that the reader treats it as an
    /// embedded dossier. Repeatable; embedded dossiers follow the
    /// `--document` list.
    #[arg(long = "embed", value_name = "FILE")]
    pub(crate) embed: Vec<PathBuf>,
    /// The creation date to write, as an RFC 3339 timestamp, normalised to
    /// UTC seconds. Without it the current time is used, which makes the
    /// output depend on the clock.
    #[arg(long, value_name = "TIME", value_parser = parse_creation_date)]
    pub(crate) created: Option<CreationDate>,
    /// Emit one stable JSON object on stdout.
    #[arg(long)]
    pub(crate) json: bool,
    /// Also accept an `--embed` dossier whose root Dossier element is in this
    /// namespace, in addition to the known-compatible ones. Repeatable.
    #[arg(long = "allow-namespace", value_name = "URI")]
    pub(crate) allow_namespace: Vec<String>,
}

impl CreateArgs {
    pub(crate) fn parse_options(&self) -> ParseOptions {
        parse_options(&self.allow_namespace)
    }
}

#[derive(Clone, Debug, Args)]
pub(crate) struct InputArgs {
    /// Input .es3 dossier, or `-` to read it from standard input.
    pub(crate) file: PathBuf,
    /// Emit one stable JSON object on stdout.
    #[arg(long)]
    pub(crate) json: bool,
    /// Also accept a dossier whose root Dossier element is in this namespace,
    /// in addition to the known-compatible ones. Repeatable.
    #[arg(long = "allow-namespace", value_name = "URI")]
    pub(crate) allow_namespace: Vec<String>,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct ExtractArgs {
    /// Input .es3 dossier, or `-` to read it from standard input.
    pub(crate) file: PathBuf,
    /// Destination directory. Existing files are never overwritten.
    #[arg(
        short,
        long,
        required_unless_present = "stdout",
        conflicts_with = "stdout"
    )]
    pub(crate) output: Option<PathBuf>,
    /// Emit one stable JSON object on stdout.
    #[arg(long, conflicts_with = "stdout")]
    pub(crate) json: bool,
    /// Also accept a dossier whose root Dossier element is in this namespace,
    /// in addition to the known-compatible ones. Repeatable.
    #[arg(long = "allow-namespace", value_name = "URI")]
    pub(crate) allow_namespace: Vec<String>,
    /// Extract only this document, named by its `object_ref` (the ds:Object Id
    /// its DocumentProfile OBJREF points at) or as `#<index>` in source order.
    /// Repeatable. Selectors never reach into an embedded dossier.
    #[arg(long = "document", value_name = "SELECTOR")]
    pub(crate) document: Vec<String>,
    /// Write the selected document's raw payload bytes to standard output and
    /// nothing else. Requires exactly one resolved, decodable document.
    #[arg(long = "stdout")]
    pub(crate) stdout: bool,
    /// Write embedded dossiers as raw payload files without expanding them.
    #[arg(long)]
    pub(crate) no_recursive: bool,
    /// Nesting levels of embedded dossiers to expand; values above 8 are
    /// clamped to 8.
    #[arg(long, value_name = "N", default_value_t = 3)]
    pub(crate) max_depth: u32,
    /// Decrypt encrypted documents with this RSA private key: PKCS#8, DER or
    /// PEM, plain or passphrase-protected. The key is read from the file and
    /// never from the command line. Without it, encrypted documents stay
    /// skipped.
    #[arg(long = "decrypt-key", value_name = "FILE")]
    pub(crate) decrypt_key: Option<PathBuf>,
    /// The certificate belonging to `--decrypt-key`, PEM or DER. It is what
    /// makes a CMS recipient recognisable; it may be omitted when the key
    /// file is PEM and carries the certificate alongside the key.
    #[arg(long = "decrypt-cert", value_name = "FILE", requires = "decrypt_key")]
    pub(crate) decrypt_cert: Option<PathBuf>,
    /// Read the passphrase of an encrypted `--decrypt-key` from this file, one
    /// trailing newline stripped. It takes precedence over the environment
    /// variable OPENSZIGNO_DECRYPT_PASSPHRASE. A passphrase is never taken
    /// from the command line.
    #[arg(
        long = "decrypt-passphrase-file",
        value_name = "FILE",
        requires = "decrypt_key"
    )]
    pub(crate) decrypt_passphrase_file: Option<PathBuf>,
    /// Also decrypt documents whose content encryption is DES-EDE3-CBC. That
    /// cipher is weak and is refused by default; it exists because it is what
    /// the Microsec reference tool encrypted with by default.
    #[arg(long = "allow-legacy-ciphers", requires = "decrypt_key")]
    pub(crate) allow_legacy_ciphers: bool,
}

impl InputArgs {
    pub(crate) fn parse_options(&self) -> ParseOptions {
        parse_options(&self.allow_namespace)
    }
}

impl ExtractArgs {
    pub(crate) fn parse_options(&self) -> ParseOptions {
        parse_options(&self.allow_namespace)
    }
}

/// The known-compatible namespaces plus whatever the caller allowed. The
/// allow-list is additive: a flag can widen it but never narrow it away from
/// the documented default.
fn parse_options(allowed: &[String]) -> ParseOptions {
    let mut namespaces: Vec<String> = KNOWN_COMPATIBLE_NAMESPACES
        .iter()
        .map(|namespace| (*namespace).to_owned())
        .collect();
    for namespace in allowed {
        if !namespaces.iter().any(|known| known == namespace) {
            namespaces.push(namespace.clone());
        }
    }
    ParseOptions {
        limits: Limits::default(),
        allowed_namespaces: namespaces,
    }
}
