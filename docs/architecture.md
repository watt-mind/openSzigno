# Architecture and CLI contract

This document is the canonical reference for the openSzigno JSON envelope,
stable codes, limits, parser safety model, and extraction policy. Anything
described here is intended to be stable for a given `schema_version`.

For upstream format sources and their relationship to code and tests, see
[ES3 specification and implementation map](es3-specification.md). That guide
distinguishes format requirements from this tool's policy and compatibility
choices; this document remains the authority for the openSzigno API.

## Goals

- Provide distributable, cross-platform binaries.
- Be safe by default when handling untrusted dossiers.
- Make every operation usable by agents: deterministic exit statuses and a
  documented JSON result.
- Separate **structural parsing/extraction** from **cryptographic validation**.

## Not yet implemented

The current release does not do the following. Until the corresponding code
exists, no output may claim or imply that anything it would have checked was
checked.

- verification of `xades:ArchiveTimeStamp`, whose imprint rules M3 declined to
  implement rather than guess at; see
  [Archive timestamps](#archive-timestamps);
- XAdES level detection (B-B, B-T, B-LT, B-LTA), scheme-level trusted-list
  `Qualifications` extensions, and signature-policy processing;
- any countersignature nesting other than a single `ds:Signature` inside an
  `xades:CounterSignature` in the countersigned signature's
  `xades:UnsignedSignatureProperties`; such a signature is reported at an
  unsupported placement and caps the dossier at `indeterminate`, never
  `invalid`. See [Countersignatures](#countersignatures);
- CMS recipient forms other than `KeyTransRecipientInfo`, and content
  encryption outside the subset in [Decryption](#decryption).

Authoring is no longer a non-goal: `create` writes a new, unsigned dossier
and encrypts its documents for a recipient, `sign` writes a signed copy of
one, and `sign --csc` signs through a remote service that holds the key.
What is still planned in [roadmap.md](roadmap.md) is a container
`es:TimeStamp`, timestamping a dossier without signing it, and the
interactive `openszigno csc login` an `oauth2`-mode credential needs; none of
the three exists yet. Nothing below is softened by any of it: `sign` produces
a signature and checks none of it, and even `--csc`, which keeps the key out
of this process entirely, asserts nothing about what it wrote (see
[remote-signing.md](remote-signing.md)).

Permanent non-goals for this tool:

- editing a dossier in place, or rewriting one it did not build;
- declaring a dossier legally valid, which is a legal judgement rather than a
  cryptographic result;
- silently accepting arbitrary XML that merely has an `.es3` suffix.

## Crate shape

```text
crates/
  openszigno-core/    # XML model, bounded decoding, transforms, stable codes
  openszigno-author/  # deterministic dossier writing: XML, MIME, ZIP, titles
  openszigno-verify/  # canonicalization, XMLDSig, certificate paths
  openszigno-cli/     # clap commands, human output, JSON protocol, exit codes
```

`openszigno-core` does not write files or print output, and it never writes a
dossier either: `openszigno-author` is the only crate that builds one, and it
does that in memory. The CLI owns all
filesystem policy and serialisation. This keeps the parser testable and makes
future library use possible without weakening CLI safety.

`openszigno-verify` is a separate crate, not a module, so that the crypto
dependency tree stays out of anyone who only wants parsing, and so that the
verification code can be audited as a unit. It performs no I/O of its own:
the clock, the trust store, and revocation data all arrive
through the injected `Clock`, `TrustSource`, and `RevocationSource` traits,
which makes "offline by default" a structural property rather than a runtime
flag someone can forget to check. It owns the whole verification pipeline —
reference resolution, the transform and algorithm allowlists, canonicalization,
and path validation — because a general-purpose XMLDSig library would own
exactly the decisions this project has stricter rules about.

Both crates read the dossier through one shared entry point,
`openszigno_core::XmlSource`, so the tree that resolves references is
byte-for-byte the tree the structural parser saw. Two parsers that disagree
about namespace scope or element boundaries is precisely the signature-wrapping
gap `verify` exists to close.

The MVP uses `roxmltree` after bounded UTF-8/ISO-8859-2 decoding for
namespace-aware XML parsing, `base64` and `zip` for bounded payload decoding,
`rustix` for descriptor-relative output on Unix, `clap` for command parsing,
and `serde`/`serde_json` for the protocol. Dependency versions and licenses
are captured by `Cargo.lock` and Cargo metadata.

### Module map: `openszigno-cli`

The binary is split along the path one run takes: parse the command line,
read the input, run the command, render the response, exit. Nothing below is
part of the public contract — it is where to look, not what is promised.

```text
crates/openszigno-cli/src/
  main.rs             # fn main: dispatch, then write the response and exit
  args.rs             # clap types, and the shared --allow-namespace plumbing
  input.rs            # the bounded reader for a file or stdin, the one every
                      #   other caller-supplied file is read with, InputInfo
  response.rs         # the JSON envelope, CliError, and its exit statuses
  render/             # writing the envelope (json.rs) and the summary (human.rs)
  commands/           # one module per command: inspect, list, validate,
                      #   extract, verify, create, sign, skill
  key_material.rs     # where a key, a certificate and a passphrase may come
                      #   from, shared by `extract --decrypt-key` and `sign`
  csc/                # `sign --csc`: the remote signing backend
    mod.rs            #   the flow and the Signer implementation
    config.rs         #   the --csc file: what it may say, and its secrets
    client.rs         #   one bounded POST per CSC operation
  extract/            # select.rs (--document), plan.rs (decode, names, nesting),
                      #   names.rs (filename safety), write.rs (writing and
                      #   rollback), output_dir.rs (race-resistant output)
  trust.rs            # --trust-store, --trust-list, and --lotl loading
  revocation_store.rs # --revocation-store loading
  online/             # --online fetching, the only code that opens a socket
    mod.rs            #   the transport, its bounds and failure classes, and
                      #     the --online-cache writer
    gaps.rs           #   what to fetch and for whom: the trust gate, coverage
                      #     at each path's own validation time, the URL order
    destination.rs    #   which URLs and addresses may be contacted at all
    pinned.rs         #   connecting only to the addresses the policy approved
```

Two boundaries are load-bearing rather than tidiness. Every command reaches
its input through `input::load` alone, so the size cap in
[Limits](#limits) cannot be bypassed by adding a command. And `extract`
plans the whole output tree — decoding, naming, and collision checking —
before `extract/write.rs` touches the filesystem, which is what makes the
all-or-nothing guarantee in [Extraction policy](#extraction-policy) possible.

### Module map: `openszigno-core`

```text
crates/openszigno-core/src/
  lib.rs      # the crate's public re-exports and the parse/parse_with_options entry points
  parse.rs    # namespace policy and the top-level Dossier parse
  xml.rs      # the shared XmlSource and id_map that verify reads too
  model.rs    # Dossier, Document, Limits, and the inventoried summary types
  sniff.rs    # DetectedType detection ahead of full parsing
  scan.rs     # structural scanning: duplicate IDs, objref resolution, warnings
  decode.rs   # decode_document_with: base64/zip decoding and the encrypt handoff
  decrypt/    # the encrypt transform; see below
  inventory.rs # signature/timestamp inventory for the JSON envelope
  error.rs    # Error, ErrorCode, and the stable-code table
```

`decrypt/` undoes the `encrypt` transform (CMS `EnvelopedData`, RFC 5652) and
is split by concern, one module per stage of that pipeline. The split is
internal; `DecryptOptions` and `RecipientKey` are the only public names, both
re-exported from `decrypt::mod` at their original path.

| Module | What it owns |
| --- | --- |
| `mod.rs` | The public entry points (`DecryptOptions`, `RecipientKey` re-export), `CmsOutcome`, and `decrypt_cms`, the orchestration that ties the other three modules together. |
| `cms` | `ContentInfo` / `EnvelopedData` / `RecipientInfo` parsing and validation, and unwrapping the content-encryption key (RSAES-PKCS1-v1_5, RSAES-OAEP). |
| `ciphers` | Content-encryption algorithm identification and AES-128/192/256-CBC and DES-EDE3-CBC decryption. |
| `keys` | Loading the recipient's PKCS#8 private key (DER or PEM, plain or passphrase-protected), PEM scanning, and certificate matching by `issuerAndSerialNumber` or `subjectKeyIdentifier`. |

### Module map: `openszigno-author`

```text
crates/openszigno-author/src/
  lib.rs      # DossierSpec/DocumentSpec, the limit checks, and build()
  render.rs   # the XML text: element order, escaping, fixed whitespace
  mime.rs     # extension to media type, and the caller's own type/subtype
  sign/       # the signer behind `sign`: mod.rs (what to sign and the three
              #   passes that fill it in), dsig.rs (ds:SignedInfo and the
              #   octets each reference digests), xades.rs (the qualifying
              #   properties), signer.rs (the Signer seam and SoftwareSigner),
              #   tsa.rs (RFC 3161 requests and responses, bytes in and out),
              #   csc.rs (CSC API v2 request bodies, response readers and the
              #     algorithm mapping; no I/O),
              #   error.rs (the codes a refused signing run reports)
  title.rs    # the title rules extraction and authoring both apply
  archive.rs  # the one-member ZIP a `zip -> base64` document carries
  encrypt/    # the CMS EnvelopedData an `encrypt` document carries
    mod.rs      # the message: content cipher, key transport, DER framing
    recipient.rs # reading a recipient certificate and naming it in CMS
  error.rs    # the stable codes a refused build reports
```

The crate reads no file, opens no socket, and calls no clock: the caller
passes the bytes, the creation date, and the signing time in, reaches the
private key through the `Signer` trait, and carries every RFC 3161 request to
the timestamp authority itself. Its one non-deterministic corner is
`encrypt/`, which draws a content key, an initialisation vector, and
key-transport padding from `OsRng`; without recipients it consults no random
source at all. See [The create command](#the-create-command) and
[The sign command](#the-sign-command).

## Format scope

- Root element `Dossier` in an allowed namespace, checked namespace-aware
  rather than by file extension. See [Namespace policy](#namespace-policy).
- XML declarations naming UTF-8 or ISO-8859-2; an absent declaration is
  treated as UTF-8. A UTF-8 byte order mark is stripped.
- Transform chains `base64`, `zip -> base64`, `encrypt -> base64`, and
  `zip -> encrypt -> base64`. The specification fixes the forward order as
  `zip? -> encrypt? -> base64`, so those four are the whole set; `encrypt` in
  any other position is an unsupported transform chain, not an encrypted
  document. A chain with `encrypt` is skipped unless `extract` was given a
  decryption key; see [Decryption](#decryption).
- Signature and timestamp material is counted for reporting only:
  `ds:Signature` elements in the XMLDSig namespace and `TimeStamp` elements in
  the dossier's own namespace.
- A document whose declared media type is `application/nldossier2`
  (case-insensitively) or whose declared extension is `dosszie` embeds another
  complete dossier; it is reported as `nested_dossier` and, by default,
  expanded recursively by `extract`.

## Namespace policy

The specification allows a dossier profile to use its own namespace as long as
it stays compliant with the default schema. openSzigno accepts an explicit
allow-list, exposed as `openszigno_core::KNOWN_COMPATIBLE_NAMESPACES`:

| Namespace | Profile |
| --- | --- |
| `https://www.microsec.hu/ds/e-szigno30#` | Default Microsec e-Szignó. |
| `http://www.e-cegjegyzek.hu/2007/e-cegeljaras#` | Hungarian company court, 2007. |
| `http://www.e-cegjegyzek.hu/2009/e-cegeljaras#` | Hungarian company court, 2009. |
| `http://www.e-cegjegyzek.hu/2012/e-cegeljaras#` | Hungarian company court, 2012. |
| `http://www.e-cegjegyzek.hu/2014/e-cegeljaras#` | Hungarian company court, 2014. |

Rules:

- The root element must be `Dossier` in one of the allowed namespaces.
  Anything else is `wrong_root`. The rejection message never echoes the
  namespace URI, which comes from untrusted input.
- Every structural lookup (`DossierProfile`, `Documents`, `Document`,
  `DocumentProfile`, `Title`, `CreationDate`, `Format`, `MIME-Type`,
  `SourceSize`, `BaseTransform`, `Transform`, `E-category`, `TimeStamp`) uses
  the dossier's *own* namespace, never the default one. `ds:Object` and
  `ds:Signature` stay in the XMLDSig namespace.
- `inspect` and `list` report the detected `namespace` verbatim, so a caller
  can tell which profile was applied.
- `--allow-namespace <URI>` (repeatable, accepted by every command) adds a
  namespace to the list. It is additive: the known-compatible namespaces are
  always accepted as well, so a flag can widen the policy but never narrow it.

### Conformance warnings

A dossier that parses but deviates from the default profile is reported
through structural warnings rather than being rejected, because real
company-court dossiers routinely deviate in these ways. The warnings carry
the codes `dangling_objref`, `document_without_profile`,
`source_size_missing`, `creation_date_missing`, and
`signature_inventory_truncated`, and never change an exit
status by themselves.

- A `Document` without `DocumentProfile` is skipped, is not counted in
  `documents`, and produces `document_without_profile` naming its source
  position among `Document` elements. The Hungarian v1.5 specification has
  an exception for a document holding only an empty `ds:Object`; the parser
  tolerates a broader set of profile-less documents. See
  [confirmed version differences](es3-specification.md#confirmed-version-differences).
- `SourceSize` is optional in a `DocumentProfile`; company-court dossiers
  occur without it. When it is present the `sizeValue`/`sizeUnit` and
  declared-size-limit rules apply unchanged and the decoded length must match
  it (`source_size_mismatch`). When it is absent the document is still read,
  `source_size` is `null`, nothing is compared against a declaration, and
  `source_size_missing` names the document index.
- `CreationDate` is optional in the `DossierProfile`; when absent the
  dossier `creation_date` is `null` and `creation_date_missing` is reported.
  A `DocumentProfile` must still carry its `CreationDate`.
- The signature inventory describes at most 64 `ds:Signature` elements and at
  most 64 `es:TimeStamp` elements. A dossier carrying more produces
  `signature_inventory_truncated`; `signatures_present` and
  `timestamps_present` still count every element. See
  [Signature inventory](#signature-inventory).
- The `DossierProfile` and every `DocumentProfile` `OBJREF` must still resolve
  exactly as before; a failure is the hard error `unresolved_objref`. Any
  other dangling `OBJREF` (a `SignatureProfile` pointing at nothing, for
  example) produces `dangling_objref` naming only the owning element's local
  name. Duplicate or empty IDs remain the hard error `duplicate_id`.

### Content sniffing

Declared MIME types are unreliable in practice, so every decoded document is
classified from a bounded prefix of its bytes by `openszigno_core::sniff`.
`pdf` and `zip` are decided by magic bytes; then, if the payload (after an
optional BOM and leading whitespace) starts with markup, the category comes
from the ASCII markup alone, so an ISO-8859-2 document is still `xml`, `html`,
or `dossier` even though its later bytes are not valid UTF-8. Only non-markup
content falls through to the UTF-8 text/binary test. The categories are
`pdf`, `html`, `xml`, `dossier`,
`zip`, `text`, and `binary`; each has a preferred extension except `binary`.
Sniffing reads at most the first 4096 bytes (1024 for a leading HTML tag),
never allocates a copy of the payload, and reports nothing about the content
beyond the category.

## Signature inventory

`inspect` and `list` describe the signature material a dossier carries. The
description is built while parsing, from the XML alone.

**Nothing in the inventory is verified.** Every field is a *claim* the dossier
makes about itself. A dossier can say that it carries a signature over the
whole container, signed at a given time, with a certificate chain and
revocation data attached, and every one of those elements can be empty, wrong,
or forged; the inventory reports what the elements say, not whether they say
anything true. It answers "what does this file claim to contain?" and never
"is any of it valid?" Only `verify` answers the second question, and it answers
it with cryptography.

Concretely, building the inventory:

- performs no cryptography of any kind: no digest, no signature check, no
  canonicalization;
- decodes nothing: no Base64 payload, no certificate, no CRL, no OCSP
  response, no RFC 3161 token. Evidence is reported as element counts, so
  `certificates: 3` means three `xades:EncapsulatedX509Certificate` elements
  were present, not that three certificates parsed;
- extracts no subject, issuer, serial number, validity date, key, or any other
  value from inside a certificate. That is deliberately out of scope here;
- resolves no reference. A `ds:Reference` URI is reported as text, and
  `reference_uris` lists same-document fragments only. Nothing is ever
  dereferenced, on the document or off it;
- parses no claimed timestamp. `claimed_signing_time` is the
  `xades:SigningTime` text with surrounding whitespace removed and nothing
  else done to it.

Placement is structural. A `ds:Signature` inside an `es:Document` is
`document` and names the document index; a direct child of the root
`es:Dossier` is `dossier`; one inside another `ds:Signature`, which a
`xades:CounterSignature` is, is `nested_in_signature` and names the enclosing
signature's `Id`; anything else is `other`, because the format does not say
what such a signature would cover. A countersignature is inventoried as an
entry of its own and contributes nothing to the entry of the signature that
carries it. Container `es:TimeStamp` elements are placed by the same rule.

Everything is bounded, because a dossier is untrusted input:

| Bound | Value | On exceeding it |
| --- | --- | --- |
| Signatures described | 64 | `signature_inventory_truncated` |
| Container timestamps described | 64 | `signature_inventory_truncated` |
| `reference_uris` per signature | 16 | The rest are not listed. |
| `xades_properties` per signature | 32 | The rest are not listed. |
| `digest_methods` per signature | 16 | The rest are not listed. |

In human mode `inspect` prints the inventory after its existing lines, one
line per signature and one per container timestamp, each prefixed with
`(unverified)`:

```text
Microsec e-Szigno dossier
Title: Synthetic signed fixture
Documents: 1
Signatures present: 2 (not verified)
Timestamps present: 1 (not verified)
Signature inventory (claimed by the dossier; nothing below was verified):
(unverified) signature 0: placement=document, document=0, id=doc-sig, references=1, xades=SigningTime+SigningCertificate, certificates=1, crls=0, ocsp=0, signature-timestamps=0, archive-timestamps=0, claimed signing time=2026-01-02T03:04:05Z
(unverified) signature 1: placement=nested_in_signature, id=counter-sig, inside=doc-sig, references=1, certificates=0, crls=0, ocsp=0, signature-timestamps=0, archive-timestamps=0
(unverified) timestamp 0: placement=dossier, includes=2, token=present
```

A dossier with no signature material prints no inventory lines at all. `list`
carries the same inventory in its JSON and its human output is unchanged.

Values that reach the output are filtered, because they come from untrusted
XML. An `Id` and a property name are echoed only when they look like a name
(ASCII alphanumerics, `-`, `_`, at most 64 characters); an algorithm URI only
when it is printable ASCII of at most 255 characters; a claimed signing time
only when it is a short token of the characters an XML dateTime uses. A value
that fails the filter is reported as `null`, or left out of its list, rather
than echoed. A reference URI that is not a same-document reference is left out
of `reference_uris` entirely, so a `reference_uris` list shorter than
`reference_count` is itself the signal that a signature references something
this listing does not show.

## Parser safety model

The parser is a bounded whole-document parser, not a streaming one. Untrusted
input passes through these stages, each with an explicit limit:

1. **Input size.** The file is read with a hard cap (`max_input_bytes`,
   64 MiB). The CLI also refuses a path that is not a regular file. Larger
   inputs fail with `input_too_large` before parsing. The file is opened once
   and both checks are made against that one open descriptor, with the cap
   enforced on the bytes that arrive; see
   [Bounded file reads](#bounded-file-reads).
2. **Encoding.** Only the `encoding` pseudo-attribute of the XML declaration
   itself is consulted; comments or later content cannot select an encoding.
   UTF-8 and ISO-8859-2 are decoded strictly; anything else is
   `unsupported_encoding` or `invalid_encoding`.
3. **Pre-parse scan.** A linear scan over the decoded text rejects any
   `<!...>` construct outside comments, CDATA sections, and processing
   instructions (`unsafe_xml`, which covers DOCTYPE and entity declarations),
   element nesting deeper than `max_xml_depth` (128), and more than
   `max_xml_nodes` (1,000,000) elements. This runs before the recursive tree
   parser, so deep nesting cannot exhaust the stack.
4. **Tree parse.** `roxmltree` parses with DTDs disabled and its own node
   limit as a backstop. Parse failures report only a line and column; element,
   attribute, and entity names from the input are never echoed.
5. **Structure.** Root element and namespace, unique non-empty unprefixed
   `Id`/`ID`/`id` attributes, `OBJREF` resolution to the direct `Documents`
   element and to exactly one direct `ds:Object` per document, required
   profile elements and attributes, and `max_documents` (256). A `SourceSize`
   that is present is bounded by `max_decoded_document_bytes` here; one that is
   absent leaves the decoded size bounded by the payload limits alone.
6. **Payload decoding.** Base64 is decoded strictly (canonical padding) with
   `max_base64_chars` and `max_decoded_document_bytes` (64 MiB) limits. ZIP
   payloads must contain exactly one regular-file member with a bare name;
   the expanded size is capped while reading, and the compression ratio
   (`max_zip_compression_ratio`, 100:1) is checked on the actual decoded
   length, not on header fields. Encrypted or non-deflate ZIP members are
   reported as `unsupported_zip_member`. The decoded length must equal the
   declared `SourceSize`.
7. **Aggregate output.** The CLI enforces `max_total_decoded_bytes` (256 MiB)
   across all documents of one extraction, counting every level of an embedded
   dossier tree against the same budget. Nesting itself is bounded by
   `--max-depth` (default 3, hard cap 8); every other limit applies unchanged
   at each level.

Peak memory is roughly a small multiple of the input size (the raw bytes, the
decoded text, the tree, and the decoded payloads are all held at once).

## Limits

The limits are compile-time defaults, reported verbatim by `inspect --json`
under `data.limits`. They bound writing as well as reading: `create` refuses
to build a dossier that would exceed any of them. They are not yet
configurable on the command line; see [roadmap.md](roadmap.md).

| Limit | Default | Enforced by | Purpose |
| --- | --- | --- | --- |
| `max_input_bytes` | 67108864 (64 MiB) | core and CLI | Raw dossier file size. |
| `max_documents` | 256 | core | `es:Document` elements per dossier. |
| `max_base64_chars` | 100663296 (96 MiB) | core | Base64 characters in one payload after whitespace removal. |
| `max_decoded_document_bytes` | 67108864 (64 MiB) | core | Decoded size of one document. |
| `max_total_decoded_bytes` | 268435456 (256 MiB) | CLI, author | Aggregate decoded size of one extraction, across the whole embedded-dossier tree, and of one `create` run. |
| `max_zip_members` | 16 | core | Members in a `zip` transform archive; the format stores exactly one, so this is defence in depth. |
| `max_zip_expanded_bytes` | 67108864 (64 MiB) | core | Expanded size of the ZIP member. |
| `max_zip_compression_ratio` | 100 | core | Expanded/compressed ratio, checked on actual decoded bytes. |
| `max_xml_depth` | 128 | core | Element nesting depth, checked before tree construction. |
| `max_xml_nodes` | 1000000 | core | Element count, checked before tree construction and again by the parser's node limit. |

## Command contract

| Command | Function | Mutates input? |
| --- | --- | --- |
| `inspect FILE` | Identify the format; return dossier metadata, the unverified signature inventory, limits, and capability warnings. | No |
| `list FILE` | Return deterministic document records, signature/timestamp presence, and the unverified signature inventory. | No |
| `extract FILE --output DIR` | Decode supported documents, and the dossiers they embed, into a new or existing directory without overwriting files. | No |
| `extract FILE --document SEL --stdout` | Decode exactly one document and write its raw payload bytes to stdout. Writes no files. | No |
| `extract FILE --decrypt-key KEY` | The same, additionally decrypting documents whose transform chain contains `encrypt`. See [Decryption](#decryption). | No |
| `validate-structure FILE` | Apply the project's strict structural rules without validating signatures. | No |
| `verify FILE` | Verify every `ds:Signature`: canonicalization, reference digests, the signature value, the e-dossier reference-scope rules, the XAdES signed `SigningCertificate` binding, RFC 3161 signature timestamps, the certificate path, and revocation. Reports a per-signature verdict of `valid`, `invalid`, or `indeterminate`. | No |
| `create --output FILE --title TITLE` | Build one new, unsigned dossier from files on disk, without overwriting anything. The only command that writes a dossier. See [The create command](#the-create-command). | No: it reads its inputs only |
| `sign FILE --output FILE --key KEY` | Write a signed copy of a dossier: one enveloped XMLDSig/XAdES signature per selected document, or one over the dossier. It verifies nothing. See [The sign command](#the-sign-command). | No: it reads its input only |
| `skill` | Write the agent skill the binary embeds (`crates/openszigno-cli/skills/openszigno/SKILL.md`) to stdout, byte for byte and with nothing added. Reads no dossier and emits no envelope. | No |

In every command except `create` and `skill` `FILE` is either a path to a
regular file or
`-`, which reads the dossier from standard input; see
[Reading from stdin](#reading-from-stdin). `create` reads no dossier and
takes no `FILE`. `skill` takes no `FILE` and no
flags of its own; see [The skill command](#the-skill-command).

These flags apply to every command that reads a dossier:

| Flag | Meaning |
| --- | --- |
| `--json` | Emit exactly one JSON object on stdout. |
| `FILE` as `-` | Read the dossier from standard input instead of from a path. The stream is capped at `max_input_bytes` and buffered in memory. |
| `--allow-namespace <URI>` | Also accept a dossier rooted in this namespace, in addition to the known-compatible ones. Repeatable. See [Namespace policy](#namespace-policy). |
| `-h`, `--help` | Print help as plain text. |
| `-V`, `--version` | Print the version as plain text. Top level only. |

`verify` has its own flags; see
[The `verify` command](#the-verify-command). `extract` additionally accepts:

| Flag | Meaning |
| --- | --- |
| `-o`, `--output <DIR>` | Destination directory; created if missing. |
| `--no-recursive` | Write an embedded dossier as a plain payload file instead of expanding it. |
| `--max-depth <N>` | Nesting levels of embedded dossiers to expand, default 3; values above the hard cap of 8 are clamped to 8. |
| `--document <SELECTOR>` | Extract only the named documents. Repeatable. See [Selecting documents](#selecting-documents). |
| `--stdout` | Write one document's raw payload bytes to stdout. See [The payload stdout mode](#the-payload-stdout-mode). |
| `--decrypt-key <FILE>` | RSA private key, PKCS#8 DER or PEM, plain or passphrase-protected, used to decrypt `encrypt` documents. See [Decryption](#decryption). |
| `--decrypt-cert <FILE>` | The certificate belonging to `--decrypt-key`, PEM or DER. Optional when the key file is PEM and carries the certificate too. Requires `--decrypt-key`. |
| `--decrypt-passphrase-file <FILE>` | Read the passphrase of an encrypted key from this file. Requires `--decrypt-key`. |
| `--allow-legacy-ciphers` | Also decrypt DES-EDE3-CBC content. Requires `--decrypt-key`. |

`create` takes no `FILE` and accepts:

| Flag | Meaning |
| --- | --- |
| `-o`, `--output <FILE>` | The dossier to write. Required. An existing file is never overwritten. |
| `--title <TITLE>` | The dossier's own title. Required. |
| `--document <PATH[::TITLE[::MIME]]>` | One document to place in the dossier. Repeatable. |
| `--zip` | Store every `--document` payload as `zip -> base64`. |
| `--embed <FILE>` | An existing dossier to embed as one document. Repeatable. |
| `--encrypt-for <CERT>` | Encrypt every `--document` payload for this recipient certificate, PEM or DER, as CMS `EnvelopedData`. Repeatable; any one recipient's private key reads the document back. An `--embed` dossier is never encrypted. See [Encrypting for a recipient](#encrypting-for-a-recipient). |
| `--legacy-key-transport` | Wrap the content-encryption key with RSAES-PKCS1-v1_5 instead of RSAES-OAEP. Requires `--encrypt-for`. |
| `--created <TIME>` | The creation date, as an RFC 3339 timestamp. Without it the current time is used. |
| `--json` | Emit exactly one JSON object on stdout. |
| `--allow-namespace <URI>` | Also accept an `--embed` dossier rooted in this namespace. Repeatable. |

`sign` takes a `FILE` and accepts:

| Flag | Meaning |
| --- | --- |
| `-o`, `--output <FILE>` | The signed dossier to write. Required. An existing file is never overwritten. |
| `--key <FILE>` | The signing key: PKCS#8, DER or PEM, plain or passphrase-protected, RSA or NIST P-256. Required unless `--csc` is given, and never taken from `argv`. |
| `--cert <FILE>` | The certificate belonging to `--key`, PEM or DER. Optional when the key file is PEM and carries the certificate too. Not accepted with `--csc`. |
| `--csc <FILE>` | Sign through a Cloud Signature Consortium API v2 service instead of a local key. The file is a small TOML table naming the service and a bearer token obtained out of band. Mutually exclusive with `--key`, `--cert`, `--passphrase-file` and `--algorithm`. See [Signing through a CSC service](#signing-through-a-csc-service). |
| `--csc-credential <ID>` | The CSC credential to sign with, overriding the configuration file. Without one the service must offer exactly one. Requires `--csc`. |
| `--passphrase-file <FILE>` | Read the passphrase of an encrypted `--key` from this file. It takes precedence over `OPENSZIGNO_DECRYPT_PASSPHRASE`. |
| `--chain <FILE>` | A certificate for `xades:CertificateValues`, so a verifier can build the signer's path without a store of its own. Repeatable; a PEM bundle may hold several. |
| `--scope <document\|dossier>` | What the signature covers. `document` (the default) writes one signature per selected document; `dossier` writes one over the whole dossier. |
| `--document <SELECTOR>` | Sign only the named documents, by `object_ref` or as `#<index>`. Repeatable. Without it every document is signed. See [Selecting documents](#selecting-documents). |
| `--tsa <URL>` | Ask this RFC 3161 timestamp authority for a token over each signature value. With `--csc`, one of the two things that make `sign` open a socket. |
| `--tsa-cert <FILE>` | A timestamp authority certificate for `xades:CertificateValues`. Repeatable. |
| `--signing-time <TIME>` | The `xades:SigningTime` to write, RFC 3339, normalised to UTC seconds. Without it the current time is used. |
| `--algorithm <NAME>` | `rsa-sha256` (default for an RSA key), `rsa-pss-sha256`, or `ecdsa-p256-sha256` (default for a P-256 key). Not accepted with `--csc`, where the credential's own `key/algo` list decides. |
| `--online-allow-private` | Permit `--tsa` and `--csc` to contact loopback, private, link-local and unique-local addresses, and permit a plain `http` CSC service. Requires `--tsa` or `--csc`. |
| `--online-proxy <URL>` | Route the `--tsa` and `--csc` requests through this proxy. Requires `--tsa` or `--csc`. |

In JSON mode, stdout contains exactly one JSON object and diagnostics go to
stderr. Document ordering is the source XML order. No command writes XML
payload bytes to stdout except `extract --stdout`, which writes the selected
document's payload and nothing else.

### Bounded file reads

Every file the CLI reads because a caller named it goes through one helper,
`input::read_bounded_file`: the dossier, `--decrypt-key` and `--key` with their
certificates and passphrase files, the `--csc` configuration and the secrets it
names, and each entry of a `--trust-store` and a `--revocation-store`.

- The path is opened once. The type and the size come from an `fstat` on that
  descriptor, and the bytes are read through it, so replacing or growing the
  file after a check cannot change what is read.
- The open refuses a symlink rather than following one, with `O_NOFOLLOW` on
  Unix and `FILE_FLAG_OPEN_REPARSE_POINT` on Windows. The dossier path is the
  one exception: it is the caller's own and has always been readable through a
  link.
- Reading stops one byte past the cap, and the file is refused at that point,
  so a reported length that is not the truth is bounded all the same. A file of
  exactly the cap is read; one byte more is not.
- On Unix the open is non-blocking (`O_NONBLOCK`), and the flag is cleared on
  the descriptor once the `fstat` above has established that it is a regular
  file. Opening a FIFO for reading otherwise blocks inside `open(2)` until
  somebody opens the writing end, which is the caller's choice and not this
  tool's, so a dossier path or a `--decrypt-key` pointing at a named pipe would
  wait indefinitely before the type check could refuse it. It now returns at
  once and is refused as not a regular file. On Windows the order is unchanged:
  the open, then the type check.

The caps are `max_input_bytes` (64 MiB) for a dossier, 1 MiB for key material
and the `--csc` configuration, 4 MiB for one trust-store entry or trusted list,
and `MAX_REVOCATION_ITEM_BYTES` (16 MiB) for one CRL or OCSP response. Each
caller words its own refusal, with the code that path already used, and no
message names the file, because the path may be private.

An input that is not a regular file, a directory most often, is `io_error`
(exit 3) with `input.bytes` reported as `null` on every operating system. A
directory has a length of its own on some filesystems and none on others, and
it is a byte count of nothing the caller asked for either way, so the envelope
says it does not know rather than repeating it.

### Reading from stdin

`FILE` may be `-`, which reads the dossier from standard input instead of from
a path. It works for every command, through the same bounded reader, and the
envelope's `input.format` and `input.bytes` are reported exactly as they are
for a file.

- At most `max_input_bytes + 1` bytes are read. Arriving at that many is
  `input_too_large` (exit 4), the same code a file over the cap produces, and
  `input.bytes` is `null` because the true size of a stream that was not read
  to its end is unknown.
- The cap is enforced on the bytes actually read, on this path and on the file
  path alike. A pipe has no filesystem metadata to consult, and a file's can
  change between a check and the read.
- The dossier is buffered in memory in full. That is inherent to the format:
  the XML must be parsed as one tree, and payloads are decoded from it.
- Standard input and standard output are independent, so `-` combines with
  `--stdout`: `openszigno extract - --document '#0' --stdout` is a valid
  filter.

### Selecting documents

`--document <SELECTOR>` restricts `extract` to the documents it names. The
flag is repeatable, and a selector is one of:

| Form | Matches |
| --- | --- |
| `#<index>` | The top-level document at that source-order index. |
| anything else | The document whose `object_ref` — the `ds:Object` `Id` its `DocumentProfile` `OBJREF` names — is exactly this string. |

- Matching is exact. A prefix of an `object_ref` matches nothing, so a
  selector cannot change meaning when a dossier gains a document.
- A selector that matches nothing is `document_not_found` (exit 4); one that
  matches more than one document is `document_ambiguous` (exit 4). The latter
  is unreachable through a parsed dossier, whose XML IDs are unique, and is
  kept because guessing would be the wrong answer.
- Selectors never reach into an embedded dossier. A selector containing `/` —
  the shape of a `dossier_path` such as `2/0` — is rejected as
  `document_not_found` with a message saying to extract the embedded dossier
  and run `extract` on the file that produced.
- Recursion is unchanged for a selected document: a selected embedded dossier
  is still written as a payload file *and* expanded into `<file>.d`, subject to
  `--no-recursive` and `--max-depth` exactly as before.
- The order of the selectors does not matter. The selection is resolved,
  deduplicated, and extracted in source order, so naming a document twice
  extracts it once.
- Every other rule is unchanged: the limits, the naming and deduplication
  rules, the no-clobber semantics, and the all-or-nothing rollback all apply
  to the selected documents.
- `skipped_count` counts only documents skipped for capability reasons —
  encryption or an unsupported transform chain — *among the selection*. A
  document that was simply not selected was never asked for and is not a skip.

### The payload stdout mode

`--stdout` writes one document's decoded payload bytes to standard output,
byte for byte, with nothing added and nothing else on the stream. Diagnostics
go to stderr. No file and no directory is created.

- `--stdout` with `--json` is a usage error (exit 2), and so is `--stdout`
  with `--output`. The JSON envelope is never redirected to stderr: exactly
  one machine-readable stream per run stays the contract.
- The run must resolve to exactly one document. Without `--document` that
  means a dossier holding exactly one document; otherwise the selection must
  name exactly one. Anything else is `stdout_requires_single_document`
  (exit 4).
- A selected document that embeds a dossier is also
  `stdout_requires_single_document` while recursion is on, because a directory
  cannot be written to a byte stream. `--no-recursive` writes its raw payload.
- A selected document that is encrypted, or whose transform chain is
  unsupported, is `document_not_extractable` (exit 5).
- A closed or failing stdout is exit 3, as everywhere else.

### The skill command

```sh
openszigno skill > .claude/skills/openszigno/SKILL.md
```

`skill` writes the Agent Skills document
`crates/openszigno-cli/skills/openszigno/SKILL.md`, embedded at build time
with `include_str!`, to stdout byte for byte and with nothing added: no
envelope, no diagnostics, no trailing newline of its own. The single
distributed binary therefore carries the skill, and installing it needs no
checkout. The command reads no dossier, takes no `FILE`, and takes no
`--json`; passing `--json` is a usage error (exit 2), as it is for
`extract --stdout`. A closed or failing stdout is exit 3, as everywhere
else.

## JSON envelope

The envelope fields are always present:

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | number | Currently `1`. |
| `ok` | boolean | `false` on any failure. |
| `command` | string | `inspect`, `list`, `extract`, `validate-structure`, `verify`, `create`, `sign`, or `usage`. `skill` never appears: it emits no envelope. |
| `input` | object | `format` is `"microsec-es3"` or `null`; `bytes` is the input size, or `null` when it is not known, which includes an input that is not a regular file and a stream that was not read to its end. |
| `data` | object or null | Command-specific; `null` on failure. |
| `warnings` | array | Objects with stable `code` and human `message`. |
| `errors` | array | Objects with stable `code` and human `message`. |

Messages never contain input paths, document titles, or payload content. On
failure `data` is `null`, `warnings` is empty, and `input.format` is `null`
when the input could not be parsed as a dossier.

**Every string in `data` that came out of the input is sanitised before the
envelope is written.** A dossier chooses its title, its document titles, its
MIME type halves, its object references, its transform names and its signature
ids, and a `verify` report adds the common names of certificates it carried.
Each of those has Unicode `Cc` and `Cf` characters dropped — the bidirectional
overrides among them — and is bounded: 256 characters for a title, 128 for
everything else, with a value that was cut short ending in `...` inside its
cap. The pass runs once, over the finished `data`, and the human summary is
rendered from that same value, so a consumer of either channel sees the same
text. Warnings and errors are filtered the same way, to 512 characters.

Two things this does not change. Field names, types and presence are exactly
what they were: sanitising alters the *content* of a string, never the shape of
the envelope, and `schema_version` stays `1`. And `extracted[].path` is left
untouched, because it has to keep naming the file that was written; the
extraction name rules ([Extraction policy](#extraction-policy)) already refuse
a title carrying such a character before a filename is derived from it.

Example, from `inspect --json` on `tests/fixtures/plain-base64.es3`. The tool
writes one compact line; this is pretty-printed:

```json
{
  "schema_version": 1,
  "ok": true,
  "command": "inspect",
  "input": { "format": "microsec-es3", "bytes": 1109 },
  "data": {
    "capabilities": {
      "base64_extraction": true,
      "cryptographic_verification": false,
      "encrypted_extraction": "with_key",
      "structural_validation": true,
      "zip_base64_extraction": true
    },
    "dossier": {
      "category": "electronic dossier",
      "creation_date": "2026-01-01T00:00:00Z",
      "documents": 1,
      "namespace": "https://www.microsec.hu/ds/e-szigno30#",
      "nested_dossiers": 0,
      "signature_inventory": {
        "signatures": [],
        "timestamps": [],
        "verified": false
      },
      "signatures_present": 0,
      "signatures_verified": false,
      "timestamps_present": 0,
      "title": "Unsigned synthetic plain fixture",
      "xml_encoding": "UTF-8"
    },
    "limits": {
      "max_base64_chars": 100663296,
      "max_decoded_document_bytes": 67108864,
      "max_documents": 256,
      "max_input_bytes": 67108864,
      "max_total_decoded_bytes": 268435456,
      "max_xml_depth": 128,
      "max_xml_nodes": 1000000,
      "max_zip_compression_ratio": 100,
      "max_zip_expanded_bytes": 67108864,
      "max_zip_members": 16
    }
  },
  "warnings": [],
  "errors": []
}
```

`data` is command-specific:

| Command | `data` fields |
| --- | --- |
| `inspect` | `dossier`, `limits`, `capabilities`. |
| `list` | `dossier`, plus `documents`: an array in source order with `index`, `title`, `creation_date`, `mime_type` (`media_type`, `subtype`, `extension`, `charset`), `source_size`, `object_ref`, `transforms`, and `nested_dossier`. `source_size` is `null` when the profile omits `SourceSize`. |
| `extract` | `extracted` (array of `document_index`, `dossier_path`, `filename`, `path`, `bytes`, `detected_type`, `declared_type`, `decrypted`), `extracted_count`, `skipped_count`, `nested_dossiers_extracted`, `selected`. |
| `validate-structure` | `valid_structure`, `documents`, `conformance_warnings`, `cryptographic_verification_performed` (always `false`). |
| `create` | `output`, `bytes`, `created`, and `documents`: an array in the order written with `index`, `title`, `mime_type`, `source_size`, `transforms`, `nested_dossier`, and `object_ref`. See [The create command](#the-create-command). |
| `sign` | `output`, `bytes`, and `signatures`: an array in the order written with `id`, `scope`, `document_index`, `algorithm`, `signing_time`, `timestamped`, and `signer` (`software` or `csc`). A `csc` entry also carries `credential_id` and `csc_specs`, the `specs` version the service reported. Neither is a secret; the bearer token never appears. See [The sign command](#the-sign-command). |
| `verify` | `verdict`, `verification_time`, `policy`, `limits`, `counts`, `checks`, `documents`, `signatures`, `timestamps`. `documents` is the per-document coverage inventory and `timestamps` the container `es:TimeStamp` reports; both are always present, as empty arrays when there is nothing to report. See [The `verify` command](#the-verify-command). |

`valid_structure` stays `true` whenever parsing succeeded;
`conformance_warnings` counts the structural deviations, which are listed
individually in `warnings`.

Each `extracted` entry describes one written file:

| Field | Meaning |
| --- | --- |
| `document_index` | Index of the document within its own dossier. |
| `dossier_path` | Position in the dossier tree: `"0"` for top-level document 0, `"2/0"` for document 0 inside nested document 2. |
| `filename` | Basename of the written file. |
| `path` | Path relative to the output root, `/`-separated, e.g. `court.dosszie.d/ruling.pdf`. |
| `bytes` | Decoded size. |
| `detected_type` | Content-sniffing result: `pdf`, `html`, `xml`, `dossier`, `zip`, `text`, or `binary`. |
| `declared_type` | The MIME essence the dossier declares, which is often wrong. |
| `decrypted` | `true` when an `encrypt` transform was reversed to produce these bytes. It says a supplied key unwrapped the content, never that anything was verified. |

`extracted_count` counts every file written across the tree, `skipped_count`
every document skipped across the tree, and `nested_dossiers_extracted` the
embedded dossiers that were expanded.

`extract --stdout` adds `decrypted` to its own `data` alongside
`stdout_bytes` and `detected_type`, with the same meaning.

`capabilities.encrypted_extraction` is the string `"with_key"`, not a boolean:
`inspect` is never given a key, so it can only report that the *tool* can
decrypt when `extract` is given one. The other capability fields stay boolean.

`selected` is the resolved `--document` selection: an array of
`{"index": <number>, "object_ref": <string>}` objects in source order, one per
selected top-level document. It is `null` when no `--document` was given, so a
consumer can tell "the whole dossier" apart from "these documents". The field
is additive; `schema_version` stays `1`.

The `dossier` object carries `title`, `category` (or `null`), `creation_date`
(or `null`),
`namespace`, `xml_encoding`, `documents` (a count), `nested_dossiers` (a count
of documents that embed a dossier), `signatures_present`, `timestamps_present`,
`signature_inventory`, and `signatures_verified`, which is always `false`.

`signature_inventory` is the unverified description of the signature material,
identical in `inspect` and `list`. It is an object with three members:
`verified`, which is always `false`; `signatures`, one entry per
`ds:Signature` in document order; and `timestamps`, one entry per container
`es:TimeStamp` in document order. `signatures_present` and `timestamps_present`
keep their meaning and still count every element, including the ones a
truncated inventory does not describe. See
[Signature inventory](#signature-inventory) for what each field means and, more
importantly, for what it does not mean.

| `signatures[]` field | Type | Meaning |
| --- | --- | --- |
| `id` | string or null | The `Id` attribute, when present and shaped like an ID. |
| `placement` | string | `document`, `dossier`, `nested_in_signature`, or `other`. |
| `document_index` | number or null | The enclosing document's index, for `document` placement. |
| `parent_signature_id` | string or null | The enclosing signature's `Id`, for `nested_in_signature`. |
| `canonicalization_method` | string or null | `ds:CanonicalizationMethod/@Algorithm`, as declared. |
| `signature_method` | string or null | `ds:SignatureMethod/@Algorithm`, as declared. |
| `digest_methods` | array | The distinct `ds:DigestMethod/@Algorithm` values of the references, in document order, at most 16. |
| `reference_count` | number | Every `ds:Reference` in `ds:SignedInfo`. |
| `reference_uris` | array | Same-document reference URIs only, at most 16. |
| `xades_namespace` | string or null | The namespace of `xades:QualifyingProperties`, when it is a recognised XAdES namespace. |
| `xades_properties` | array | Local names of the signed and unsigned qualifying properties present, in document order, at most 32. |
| `evidence` | object | `certificates`, `crls`, `ocsp_responses`, `signature_timestamps`, `archive_timestamps`: element counts. |
| `claimed_signing_time` | string or null | The `xades:SigningTime` text, trimmed and otherwise unparsed. |
| `key_info_certificates` | number | `ds:X509Certificate` elements under `ds:KeyInfo`. |

| `timestamps[]` field | Type | Meaning |
| --- | --- | --- |
| `placement` | string | `dossier`, `document`, or `other`. |
| `document_index` | number or null | The enclosing document's index, for `document` placement. |
| `include_count` | number | `xades:Include` children, counted; none is resolved. |
| `has_token` | boolean | A non-empty `xades:EncapsulatedTimeStamp` is present. |

Example of a failure envelope, from `inspect --json` on
`tests/fixtures/doctype.es3` (exit status 4):

```json
{
  "schema_version": 1,
  "ok": false,
  "command": "inspect",
  "input": { "format": null, "bytes": 366 },
  "data": null,
  "warnings": [],
  "errors": [
    {
      "code": "unsafe_xml",
      "message": "DTD and entity declarations are not allowed"
    }
  ]
}
```

### Contract tests

The envelope above is not only described here; it is captured. `tests/golden/`
holds the stdout and exit status of every command over every fixture in
`tests/fixtures/`, in both `--json` and human mode, and CI's `golden` job
compares the built binary against those files on every pull request. A change
to any golden file is a change to this contract and is reviewed with the
`schema_version` rule in mind: an added field, warning code, check code, or
human line is additive, keeps `schema_version` at `1`, and needs the goldens
regenerated and a `CHANGELOG.md` entry; a removed or renamed field, a changed
type, or a changed exit status for an existing outcome needs a
`schema_version` bump in the same pull request. Only two values are masked,
both clock-dependent times; the rules are in `tests/golden/README.md`.

## Exit statuses

Exit statuses are stable at the category level:

| Status | Meaning |
| --- | --- |
| `0` | Operation completed (possibly with explicit skipped-document warnings). |
| `2` | Command-line usage error, emitted by `clap`. |
| `3` | Input/output error. |
| `4` | Invalid, unsupported, or unsafe dossier structure, or unusable decryption material. |
| `5` | Payload decoding or safe-extraction failure. |
| `6` | `verify` completed and at least one signature verdict is `invalid`. |
| `7` | `verify` completed, no signature is `invalid`, and the overall verdict is `indeterminate`. |

`skill` uses only `0`, `2` and `3`: it writes the embedded document, a
usage error, or nothing at all when stdout cannot be written.

Statuses 6 and 7 describe a run that *completed*: the dossier parsed, the
signatures were examined, and the tool is reporting what it found. A structural
failure during `verify` still exits 4, so a caller can tell "this is not a
dossier" apart from "this dossier's signatures do not verify".

`verify` exits `0` when the overall verdict is `valid`, which means every
signature in the dossier is `valid` and every check on each of them passed —
see [Verdicts](#verdicts) for exactly what that requires and
[Verification boundary](#verification-boundary) for what it does not mean. A
missing trust store, a trusted list whose own signature was not checked,
missing revocation data, and `--no-revocation` all exit `7`, never `0`.

Failures have `ok: false`, stable machine-readable error codes, and a nonzero
exit status. An unsupported encrypted document is a successful parse with an
explicit capability warning; malformed or unsafe input is an error.

Usage errors (exit 2) are produced before a command runs. Without `--json`
they are `clap`'s human text on stderr with empty stdout. When `--json` is
present on the command line, the standard envelope is written instead with
`command: "usage"` and the error code `usage_error`; the message is a fixed
string, because `clap`'s own text can quote argument values that may be
private paths. `--help` and `--version` always print plain text. If stdout
cannot be written (for example a closed pipe), the process exits with status 3
without printing a panic.

## Stable codes

Error codes and the exit status they map to. Codes marked *core* come from
`openszigno_core::ErrorCode`; codes marked *CLI* are produced by the CLI's
I/O and extraction policy.

| Code | Origin | Exit | Meaning |
| --- | --- | --- | --- |
| `usage_error` | CLI | 2 | Invalid command line (JSON mode only). |
| `io_error` | CLI | 3 | The input could not be inspected, opened, or read; or output could not be created or written for a reason other than a pre-existing file. |
| `input_too_large` | core, CLI | 4 | Input exceeds `max_input_bytes`. |
| `unsupported_encoding` | core | 4 | The XML declaration names an encoding other than UTF-8 or ISO-8859-2. |
| `invalid_encoding` | core | 4 | Bytes are not valid for the declared encoding. |
| `unsafe_xml` | core | 4 | DTD/entity declaration, nesting depth, or node count limit. |
| `invalid_xml` | core | 4 | Not well-formed XML, or a required element occurs more than once where one is required. |
| `wrong_root` | core | 4 | Root is not `Dossier`, or its namespace is not allowed. |
| `missing_element` | core | 4 | A required element is absent or empty. |
| `invalid_attribute` | core | 4 | A required attribute is absent or malformed. |
| `duplicate_id` | core | 4 | An XML ID is empty or repeated. |
| `unresolved_objref` | core | 4 | An `OBJREF` does not resolve to exactly one ID, or not to the expected element. |
| `too_many_documents` | core, author | 4 | More than `max_documents` documents, read or written. |
| `decoded_too_large` | core, author, CLI | 4 or 5 | A declared or decoded payload exceeds a size limit (4 when detected during parsing or while building a dossier, 5 during extraction). `create` also reports it for an input file over `max_decoded_document_bytes`. |
| `invalid_base64` | core | 5 | Payload is not canonical Base64. |
| `source_size_mismatch` | core | 5 | Decoded length differs from the declared `SourceSize`. |
| `invalid_zip` | core | 5 | ZIP payload is malformed or cannot be expanded. |
| `zip_member_limit` | core | 5 | The archive does not contain exactly one member. |
| `zip_size_limit` | core | 5 | The ZIP member exceeds the expanded-size limit. |
| `zip_ratio_limit` | core, author | 4 or 5 | The ZIP member exceeds the compression-ratio limit (4 when `create --zip` refuses to write one, 5 when extraction refuses to expand one). |
| `unsafe_zip_member` | core | 5 | The member is a directory, a symlink, or has a non-basename path. |
| `unsupported_zip_member` | core | 5 | The member uses encryption or an unsupported compression method. |
| `invalid_decryption_key` | core | 4 | `--decrypt-key` is not an RSA private key in PKCS#8 DER or PEM form, or its passphrase is missing or wrong. The two are deliberately not told apart. |
| `invalid_decryption_certificate` | core | 4 | `--decrypt-cert`, or the certificate inside the key file, is not a readable X.509 certificate with an RSA public key. |
| `decryption_certificate_required` | core | 4 | `--decrypt-key` was given with no certificate, and the key file carries none. Without one the recipient this key belongs to cannot be recognised. |
| `decryption_key_mismatch` | core | 4 | The certificate's public key is not the given key's public key. |
| `invalid_cms` | core | 5 | An encrypted payload is not a well-formed CMS `EnvelopedData` `ContentInfo`, carries no encrypted content, or has a malformed initialisation vector or block length. |
| `decrypt_failed` | core | 5 | Decryption failed. The message is exactly `decryption failed` and never says which step failed. |
| `no_documents` | author | 4 | `create` was given no `--document` and no `--embed`. |
| `unsafe_document_title` | author | 4 | A `create` document title fails the rules extraction applies to a filename, so the dossier would not be extractable. |
| `invalid_dossier_title` | author | 4 | The `create --title` value is empty, over 1024 bytes, or holds a control character. |
| `unknown_mime_type` | author | 4 | No media type is registered for a `create` document's extension and none was given. |
| `invalid_mime_type` | author | 4 | A `create` document's media type is not a bare `type/subtype`. |
| `zip_failed` | author | 4 | A `create --zip` payload could not be packed into a ZIP archive. Not reachable through any input this tool accepts. |
| `invalid_recipient_certificate` | author, CLI | 4 | A `create --encrypt-for` file is not a readable X.509 certificate, in DER or in a PEM `CERTIFICATE` block, or is larger than 1 MiB. |
| `unsupported_recipient_key` | author | 4 | A `create --encrypt-for` certificate carries a public key that is not RSA, or an RSA key too small to wrap the content-encryption key. |
| `no_recipients` | author | 4 | Encryption was asked for with no recipient certificate. Unreachable through the CLI, which only builds an encryption request from `--encrypt-for`. |
| `encrypt_failed` | author | 4 | The CMS `EnvelopedData` could not be built. Not reachable through any input this tool accepts: every value in it is built by this tool and within every bound the DER encoders check. |
| `invalid_signing_key` | author | 4 | `--key` is not an RSA or NIST P-256 private key in PKCS#8 DER or PEM form, its passphrase is missing or wrong, or `--algorithm` names a scheme that key cannot produce. "Wrong passphrase" is deliberately not told apart from "not a PKCS#8 file". |
| `invalid_signing_certificate` | author | 4 | `--cert`, `--chain`, `--tsa-cert`, or the certificate inside the key file is not a readable X.509 certificate. |
| `signing_certificate_required` | author | 4 | `--key` was given with no `--cert` and the key file carries none, so nothing would bind the signature to a certificate. |
| `signing_key_mismatch` | author | 4 | The certificate's public key is not the signing key's public key. |
| `document_not_signable` | author | 4 | A selected document has no payload `ds:Object` or no `es:DocumentProfile` with an `Id`, so the mandated reference set cannot be written for it; or the dossier holds a value a signature would have to quote and cannot: an `Id`/`OBJREF` that is not an XML NCName, a media type outside the token characters, or a namespace URI holding markup, a quote character or a control character. See [Nothing the dossier says decides what is signed](#nothing-the-dossier-says-decides-what-is-signed). |
| `document_already_signed` | author | 4 | Adding this signature would invalidate one the dossier already carries. See [Signing a dossier that is already signed](#signing-a-dossier-that-is-already-signed). |
| `tsa_failed` | author, CLI | 5 | The `--tsa` request could not be made, was refused by the destination policy, or the answer was not a granted RFC 3161 response carrying a token over the requested imprint. The message names the reason. |
| `csc_config_invalid` | CLI, author | 4 | The `--csc` configuration file cannot be used (a missing or empty key, an unknown key, a value outside the accepted TOML subset, a `redirect_uri` that is not a loopback URI, or a plain `http` `base_url` without `--online-allow-private`), or the service it names does not report a CSC API v2 `specs` version or will not sign a data-to-be-signed representation. Nothing is contacted and nothing is written. |
| `csc_unreachable` | CLI | 5 | A CSC operation could not be carried out at all. The message names the operation and the transport's own failure class (`timeout`, `destination_refused: …`, `http status …`, `too large`, `redirect`, `invalid`, `transport`). |
| `csc_rejected` | CLI, author | 5 | The service answered and what it answered cannot be used. The message carries the operation, the HTTP status and the service's own `error` string, bounded and stripped of control characters. `error_description` is never quoted, and neither is the bearer token. |
| `csc_credential_ambiguous` | author | 4 | The account holds several signing credentials and none was named. The message lists the identifiers; pass one as `--csc-credential`. |
| `csc_credential_unusable` | author | 4 | The named credential cannot produce a signature this build writes: its key or certificate is not enabled or valid, it published no certificate or no algorithm, its certificate is unreadable, or its `key/algo` list offers nothing this build writes, including RSASSA-PSS with no `signAlgoParams`, which would mean guessing the salt length. |
| `csc_authorization_required` | author | 4 | The credential's authorisation mode is `oauth2`, which needs a second OAuth 2.0 round with `scope=credential` and therefore a browser. This build is non-interactive; see [Signing through a CSC service](#signing-through-a-csc-service). |
| `csc_signature_invalid` | author | 5 | The signature the service returned does not verify against the certificate it published. Nothing is written. A hash-only service signs a digest it never sees the document behind, so this is the one check that tells a right signature from a well-formed wrong one. |
| `sign_failed` | author | 5 | Signing could not be completed: an identifier the signature needs is already used in the dossier, an element could not be canonicalized, or the key refused to sign. |
| `invalid_output_path` | CLI | 4 | The `create --output` or `sign --output` path does not name a file. |
| `unsafe_output_name` | CLI | 5 | A document title or declared extension cannot be used as a filename, or the derived `<file>.d` directory name would be too long. |
| `output_name_collision` | CLI | 5 | Residual: two outputs still map to the same name in one directory after all 64 deduplicated candidates were taken. |
| `output_exists` | CLI | 5 | A destination file already exists or cannot be created safely. |
| `document_not_found` | CLI, author | 4 | A `--document` selector matches no document, is not a decimal index after `#`, or names a document inside an embedded dossier. `sign` reports it for its own selectors. |
| `document_ambiguous` | CLI | 4 | A `--document` `object_ref` selector matches more than one document. Unreachable through a parsed dossier, whose XML IDs are unique. |
| `stdout_requires_single_document` | CLI | 4 | `--stdout` did not resolve to exactly one document, or the one it resolved to embeds a dossier while recursion is on. |
| `document_not_extractable` | CLI | 5 | The document `--stdout` selected is encrypted or uses an unsupported transform chain. |
| `trust_store_invalid` | CLI | 3 | `--trust-store` does not name a readable directory, holds a file that is not PEM or DER certificate data, or holds no trust anchor. A partially loaded store would silently change what "trusted" means, so the run fails instead. |
| `trust_list_invalid` | CLI | 3 | A `--trust-list`, `--lotl`, or `--trust-list-signer` file could not be read or parsed. A trusted list that loaded only in part would silently change what "trusted" means, so the run fails instead. |
| `revocation_store_invalid` | CLI | 3 | `--revocation-store` does not name a readable directory, holds more files than the loader will read, holds a file larger than `MAX_REVOCATION_ITEM_BYTES`, or holds a file that is neither a CRL nor an OCSP response. |
| `online_options_invalid` | CLI | 3 or 4 | The network transport could not be built, which today means `--online-proxy` is not a usable proxy URL. `verify --online` reports it as exit 3; `sign --tsa` and `sign --csc` report it as exit 4. |
| `online_cache_invalid` | CLI | 3 | The `--online-cache` directory could not be opened safely, or a cache file could not be written. A name inside it that already holds something else is not this error; that is one `online_fetch_failed` with the class `cache_collision`, and the run continues. |
| `unsafe_output_directory` | CLI | 5 | The output path contains a symlink or reparse point, or is not a real directory. |
| `total_size_limit` | CLI, author | 4 or 5 | Aggregate decoded size exceeds `max_total_decoded_bytes` (4 when `create` refuses to write, 5 during extraction). |

Warning codes. Warnings never change the exit status by themselves:

| Code | Emitted by | Meaning |
| --- | --- | --- |
| `cryptographic_verification_not_performed` | all commands | Signature or timestamp material is present but was not verified. |
| `encrypted_document_unsupported` | all commands | A document declares the `encrypt` transform, and this run holds no decryption key. `extract --decrypt-key` does not emit it; what happened to each document is reported per document instead. |
| `unsupported_transform_chain` | all commands | A document uses a transform chain other than `base64` or `zip -> base64`. |
| `document_skipped_encrypted` | `extract` | An encrypted document was not extracted. |
| `document_skipped_unsupported_transform` | `extract` | A document with an unsupported transform chain was not extracted. |
| `document_skipped_no_matching_recipient` | `extract` | No CMS `RecipientInfo` names the certificate given with `--decrypt-key`. |
| `document_skipped_unsupported_cipher` | `extract` | The message uses a key-transport or content-encryption algorithm outside the supported subset. The message names its OID. |
| `document_skipped_legacy_cipher` | `extract` | The content is DES-EDE3-CBC and `--allow-legacy-ciphers` was not given. The message names its OID. |
| `dangling_objref` | all commands | An `OBJREF` outside the dossier and document profiles resolves to no XML ID. |
| `document_without_profile` | all commands | A `Document` has no `DocumentProfile` and was skipped. |
| `source_size_missing` | all commands | A `DocumentProfile` declares no `SourceSize`, so the decoded length is not checked against one. |
| `creation_date_missing` | all commands | The `DossierProfile` declares no `CreationDate`; the dossier `creation_date` is `null`. |
| `signature_inventory_truncated` | all commands | More than 64 `ds:Signature` or 64 `es:TimeStamp` elements are present, so the inventory describes only the first 64 of that kind. `signatures_present` and `timestamps_present` still count them all. |
| `output_name_deduplicated` | `extract` | A document's output name was already taken in its directory, so it was renamed. |
| `nested_dossier_depth_limit` | `extract` | An embedded dossier was kept as a file because `--max-depth` was reached. |
| `recipient_certificate_expired` | `create` | An `--encrypt-for` certificate has already expired; the document was encrypted for it anyway, because decryption never consults a recipient certificate's validity. The message names the recipient by its position on the command line. |
| `created_dossier_unsigned` | `create` | The dossier that was written carries no signature and no timestamp. Every successful `create` reports it, last. |
| `signed_dossier_unverified` | `sign` | A signature was produced and nothing was checked. Every successful `sign` reports it. |
| `csc_config_permissive` | `sign --csc` | The `--csc` configuration file is readable by other users on this machine and may hold a bearer token. The mode is never enforced, only reported. Unix only. |
| `csc_key_unused` | `sign --csc` | The configuration names `redirect_uri`, `client_secret` or `client_secret_file`, which belong to the interactive `csc login` flow and are not used by this run. |
| `nested_dossier_invalid` | `extract` | An embedded dossier could not be parsed; the raw payload was kept and the run continued. |

## The `verify` command

`verify` is the M2 milestone. This release ships **phase 3**, which completes
it: the XMLDSig core, the XAdES signed properties, RFC 3161 signature
timestamps, certificate-path validation against a caller-supplied trust store
and ETSI TS 119 612 trusted lists, and offline revocation checking.

With revocation implemented, `valid` is reachable — and reachable only when
every emitted check passed. A caller that sees `indeterminate` has learned that
nothing failed, not that anything is trustworthy. `valid` means every check
this build makes passed at the stated validation time; it is not a legal
opinion, and [Verification boundary](#verification-boundary) says what it does
not cover.

```text
openszigno verify FILE [--json]
    --trust-store DIR           # anchors, and optional extra CA certificates
    --trust-list FILE           # ETSI TS 119 612 trusted list, repeatable
    --lotl FILE                 # EU list of trusted lists; names their signers
    --trust-list-signer CERT    # certificate that must have signed each list
    --revocation-store DIR      # CRLs and OCSP responses, offline
    --no-revocation             # switch revocation off; caps at indeterminate
    --online                    # fetch what offline data does not cover
    --online-cache DIR          # write what --online fetched, store-shaped
    --online-proxy URL          # the only proxy --online will ever use
    --online-allow-private      # permit loopback/private --online destinations
    --at <RFC3339>              # validation time; overrides any timestamp
    --allow-legacy-algorithms   # admit SHA-1 for diagnosis only
    --allow-namespace URI       # as on every other command, repeatable
```

| Flag | Meaning |
| --- | --- |
| `--trust-store <DIR>` | Directory of trust anchors (`anchors/*`, PEM or DER) and optional extra CA certificates (`intermediates/*`). A directory of certificates with no `anchors` subdirectory is read as anchors. Without it, every chain check is `unknown`. See [Trust store](#trust-store). |
| `--trust-list <FILE>` | ETSI TS 119 612 trusted list (XML) to take trust anchors from. Repeatable. Its anchors join the `--trust-store` ones, each reported with its origin, and only these can make a chain `qualified`. Nothing is fetched. See [Trusted lists](#trusted-lists). |
| `--lotl <FILE>` | EU list of trusted lists (XML). Its `PointersToOtherTSL` entries name the national lists' signing certificates, so one out-of-band certificate bootstraps every `--trust-list`. The LOTL is verified against `--trust-list-signer` first and contributes no trust anchors of its own. |
| `--trust-list-signer <CERT>` | Certificate, PEM or DER, that must have signed the `--lotl` and, absent one, every `--trust-list`. Obtain it out of band; for the EU list of trusted lists, from the Official Journal. Without any signer the lists are read but reported `trust_list_unverified`, which caps the verdict at `indeterminate`. |
| `--revocation-store <DIR>` | Directory of CRLs (`crls/`) and OCSP responses (`ocsp/`), DER or PEM, checked in addition to the signature's own `xades:RevocationValues`. A flat directory works too; each file is classified by what it contains. Nothing is ever fetched. See [Revocation](#revocation). |
| `--no-revocation` | Do not check revocation at all. Emits `revocation_not_checked`, which is blocking, so this produces at most `indeterminate`. Cannot be combined with `--online`. |
| `--online` | Fetch revocation data the offline material does not cover, from the CRL distribution points and AIA OCSP responders the certificates themselves publish, and only for certificates on a path openSzigno validated to a configured trust anchor. With no trust material nothing is fetched at all. The only thing that makes openSzigno touch the network. See [Online revocation fetching](#online-revocation-fetching) for the timeouts, size caps, and destination rules. |
| `--online-cache <DIR>` | Write everything `--online` fetched into `DIR` in the `--revocation-store` layout, so a later run with `--revocation-store DIR` and no `--online` reproduces the result with no network at all. Files are created relative to an opened directory descriptor and never follow a symlink; nothing existing is ever truncated or replaced. Requires `--online`. |
| `--online-proxy <URL>` | Route `--online` fetches through this proxy. Without it no proxy is used: `HTTP_PROXY` and its relatives are deliberately ignored. Requires `--online`. |
| `--online-allow-private` | Permit `--online` to contact loopback, private (RFC 1918), link-local and unique-local addresses and the host name `localhost`, which are refused by default because the URL comes out of a certificate the run has not yet established trust in. For an internal CA that really does publish there. Requires `--online`. |
| `--at <RFC3339>` | Validation time. It overrides everything: without it, a signature whose timestamp verified completely is validated at that token's `genTime`, and otherwise at the current time. See [Validation time](#validation-time). |
| `--allow-legacy-algorithms` | Admit SHA-1 digests and RSA-SHA1 signature methods for diagnosis only: they emit `algorithm_legacy_allowed` instead of a passed check, the verdict stays capped at `indeterminate`, and no failed check can become a passed one. MD5, HMAC, DSA, and RSA keys below 2048 bits stay refused. See [Algorithm policy](#algorithm-policy). |

Offline is the default and `openszigno-verify` is network-free by
construction: it opens no socket in any mode, and revocation data reaches it
only through the injected `RevocationSource`. `--online` does not change that.
It permits the **CLI** to fetch CRLs and OCSP responses that the caller's own
material does not cover, from the URLs published by certificates that sit on a
path to a configured trust anchor, and to hand what comes back to the verifier
through the same seam a `--revocation-store` file arrives through. With no
anchor configured nothing is fetched at all. See [Online
revocation](#online-revocation-fetching).

Reference resolution is strictly same-document in every mode — a `ds:Reference`
or an `xades:Include` never reaches the network or the filesystem, with or
without `--online` — and the trust store, the trusted lists, and the revocation
store remain the only external material a run consults on its own.
[trust.md](trust.md) describes how to obtain and lay out all of them.

### Verification pipeline

Per `ds:Signature`, in document order, stopping early where continuing would be
meaningless:

1. **Structure and policy.** The element children of `ds:Signature`, its
   `ds:SignedInfo`, and each `ds:Reference` match the cardinality and order
   the XMLDSig schema fixes (see
   [XMLDSig structural rules](#xmldsig-structural-rules)); the signature sits
   at `//es:Document/ds:Signature`,
   `//es:Dossier/ds:Signature`, or inside an `xades:CounterSignature` (see
   [Countersignatures](#countersignatures)); the canonicalization, signature,
   and digest algorithms are inside the pinned allowlist; every transform is
   inside the transform allowlist; every reference URI is `""` or `#id`; every `#id`
   resolves to exactly one node in the ID space `openszigno-core` validated;
   and the mandated e-dossier reference set is covered. Any failure here makes
   the verdict `invalid` and the later stages are not attempted — there is no
   point digesting a reference chain the policy already refused.
2. **Cryptography.** Each reference is resolved to a node set, its transform
   chain applied, the result canonicalized, and its digest recomputed and
   compared. `ds:SignedInfo` is canonicalized and `ds:SignatureValue` verified
   against the signing certificate (see
   [Signing-certificate selection](#signing-certificate-selection)).

   A same-document reference dereferences to a node set **with its comments
   already removed**, as XMLDSig 4.4.3.3 requires, so a with-comments transform
   applied afterwards still sees none and inserting a comment into a signed
   element cannot change its digest. The `#xpointer(...)` forms that would keep
   comments are not supported and are refused as external references.
3. **XAdES.** The signed `SigningCertificate` / `SigningCertificateV2`
   property is read and the certificate it digests is required to be the one
   whose key verified the signature (see
   [XAdES signed properties](#xades-signed-properties)). `SigningTime` and the
   signature policy identifier are reported and never acted on. Any
   qualifying property this build does not process is named rather than
   ignored.
4. **Timestamps.** Every `xades:SignatureTimeStamp` token is parsed, its
   imprint recomputed over the canonicalized `ds:SignatureValue`, the TSA
   signature verified, the TSA certificate's `extendedKeyUsage` checked, and
   its path validated to an anchor at the token's `genTime` (see
   [Signature timestamps](#signature-timestamps)).
5. **Certificate path.** The signing certificate is the one the signed XAdES
   property designates, falling back to the `ds:KeyInfo` candidate whose key
   verified the signature; a path is then built from it through the other
   candidate certificates to a configured anchor and validated at this
   signature's [validation time](#validation-time).
6. **Revocation.** Every certificate in the signer's chain except the trust
   anchor, and every certificate in each timestamp authority's chain except its
   anchor, is checked against the signature's own `xades:RevocationValues` and
   the revocation store (see [Revocation](#revocation)). The anchor is never
   asked about: its revocation is not a question the PKI it roots can answer,
   and asking would invite a self-signed CRL to speak for itself.

### XMLDSig structural rules

Stage A1 reads each critical child of a signature by name. That is only sound
once something has established that exactly one such child exists, in the
position the schema puts it: a second `ds:SignatureValue` appended after the
real one, or a `ds:DigestValue` placed before its `ds:DigestMethod`, would
otherwise let one consumer read what another ignores while openSzigno still
reported the first copy as verified.

So stage A1 first walks the element children of `ds:Signature`, of its
`ds:SignedInfo`, and of each `ds:Reference` in document order and checks the
sequence against the XMLDSig schema:

| Element | Required sequence |
| --- | --- |
| `ds:Signature` | one `ds:SignedInfo`, one `ds:SignatureValue`, at most one `ds:KeyInfo`, then zero or more `ds:Object`. |
| `ds:SignedInfo` | one `ds:CanonicalizationMethod`, one `ds:SignatureMethod`, then one or more `ds:Reference`. |
| `ds:Reference` | at most one `ds:Transforms`, then one `ds:DigestMethod` and one `ds:DigestValue`. |

A duplicated child, a child out of that order, or a child the sequence does not
name is a `sig_structure_invalid` failure whose message says which element and
which of the three it is. The verdict is `invalid`, as it is for every failed
check, and no later stage runs, so such a signature can never reach a passed
`signature_value_ok`.

The schema's extension points stay open. The content of `ds:Object` and of
`ds:KeyInfo` is unconstrained here and is never inspected by this pass, so
XAdES `xades:QualifyingProperties`, which live inside a `ds:Object`, and any
key material a `ds:KeyInfo` carries are unaffected. The `Id` attribute of
`ds:Signature` is untouched. Whitespace text and comments between children are
ignored, so an indented signature reads the same as a compact one. What the
schema does *not* allow is a foreign-namespace element as a direct child of
`ds:Signature`, `ds:SignedInfo`, or `ds:Reference`, so one appearing there is a
structure error too.

Only duplication, order, and unexpected children are decided by this pass. A
required element that is simply absent is reported by the same code with the
message it always had.

### Module map

`openszigno-verify` is organised as the pipeline above, one module per stage.
The split is internal; the crate's public API is unchanged.

| Module | What it owns |
| --- | --- |
| `lib.rs` | The `verify` entry point: the run's `Context`, the per-signature loop through stages A to F, and the dossier-level assembly (container timestamps, coverage, counts, verdict). |
| `dsig` | The shared `Context` and the small XML helpers every stage is built from, plus re-exports of the items that used to live here. |
| `references` | One `ds:Reference`: parsing, same-document resolution on the validated ID space, the transform allowlist and its application, the effective node set (`ReferenceScope`) every coverage rule shares, and digest recomputation. |
| `scope` | Placement classification (`Placement`, `placement_of`), the mandated e-dossier reference sets, and `reference_scope_check`. |
| `countersign` | Countersignature detection, the binding check, and the reported role, parent and `countersigns` set. |
| `signature` | The per-signature driver (stages A and B): `structure.rs` checks XMLDSig cardinality and order before anything is read by name, `signed_info.rs` parses `ds:SignedInfo` and applies the signature-level algorithm policy, `collect.rs` gathers the timestamp tokens and the octets each one covers, and `mod.rs` keeps signer selection and `ds:SignatureValue` verification. |
| `coverage` | What a signature's resolved references cover, and the per-document coverage report and its dossier-level checks. |
| `xades` | Stage C: the XAdES qualifying properties and the signed `SigningCertificate` binding. |
| `certs` | Stage D: `extensions.rs` decodes a certificate's extensions, `purpose.rs` holds the `extendedKeyUsage` policy per `PathPurpose`, `names.rs` implements RFC 5280 name constraints, `path.rs` builds and validates a path, and `mod.rs` keeps the public types, `check_path` and public-key signature verification. |
| `revocation` | Stage E: `crl.rs` validates and looks up CRLs, `ocsp.rs` validates OCSP responses and the RFC 6960 responder-authorisation models, `tiers.rs` holds the source priority, coverage and fallback rules with the summaries and messages they produce, and `mod.rs` keeps the public API and `check_path`. |
| `tsa` | Stage F: `token.rs` holds the RFC 3161 wire formats and the CMS signed-attribute checks, `imprint.rs` the digest allowlist and the imprint recomputation, `path.rs` the TSA certificate's purpose and its path at `genTime`, and `mod.rs` the token driver and `verify_signature_timestamps`. |
| `estimestamp` | The container's own `es:TimeStamp` elements and what they cover, including the `xades:Include` data selection. |
| `trustlist` | ETSI TS 119 612 trusted lists: `parse.rs` reads the XML, `services.rs` evaluates the status timeline and the pre-eIDAS rules, `qualified.rs` decides a validated chain's qualified status, and `mod.rs` keeps the public API and the verification of the list's own signature. |
| `trust`, `policy`, `codes`, `report`, `c14n`, `embedded` | The injected I/O seams, the pinned algorithm and limit policy, the check codes, the JSON report types, canonicalization, and the whole-document reads the CLI's `--online` fetcher needs. |

Each of those directory modules re-exports every public item at the path it
had before the split, so the crate's public API is unchanged.

`scripts/check-file-length.py`, run in CI, keeps a new `src` file under 800
lines and a new `tests` file under 1500 (see
[CONTRIBUTING.md](../CONTRIBUTING.md)); no module of this crate is named in
`scripts/file-length-allowlist.txt` any more, and none of its source files
exceeds the limit.

### Reference scope

Because the e-dossier specification mandates *which elements* a signature must
reference, `verify` enforces reference-scope completeness. This is the
strongest defence against XML signature wrapping, and it is a check a generic
XMLDSig library cannot perform, because it depends on the container's
semantics rather than on what the signature claims about itself.

| Placement | `placement` | Must cover |
| --- | --- | --- |
| `//es:Document/ds:Signature` | `document` | the document's `es:DocumentProfile`, the document's payload `ds:Object`, the signature's own signature-profile object, and, when XAdES qualifying properties are present, the `xades:SignedProperties`. |
| `//es:Dossier/ds:Signature` | `dossier` | `/es:Dossier/es:DossierProfile`, `/es:Dossier/es:Documents`, the signature's own signature-profile object, and the same `xades:SignedProperties`. |
| the `ds:Signature` inside an `xades:CounterSignature` | `countersignature` | the countersigned signature's `ds:SignatureValue`, its own `xades:SignedProperties`, and its own signature-profile object **when it carries one**. Nothing about documents: a countersignature attests the parent signature, not the payload. See [Countersignatures](#countersignatures). |
| any other nesting | `unknown` | undefined. This is the *unsupported placement* state; the mandated set is `reference_scope_unknown`. |

#### The effective node set

A reference covers a required element when that element is in the reference's
**effective node set**: what the reference actually digests, once its transform
chain has been applied to the node set it dereferenced. Resolution alone does
not answer the question, because a transform can *remove* nodes from that set.

| Transform | Effect on membership |
| --- | --- |
| enveloped-signature | Removes the whole `ds:Signature` the reference is written in. XMLDSig 1.1 clause 6.6.4: it "removes the whole `Signature` element containing T from the digest calculation of the `Reference` element containing T". |
| the canonicalization algorithms | None. Canonicalization chooses how the set is serialized, never which nodes are in it. |
| base64 | The reference becomes an octet stream over the resolved node's text, so it covers that node and no element structure beneath it: rearranging the elements inside a base64-referenced object need not change the octets. |

Coverage is then containment minus exclusion: the required element is the
resolved node or a descendant of it, and no removed subtree lies on the path
from it to the document root — an exclusion *above* the resolved node removes
that node too. So a `URI=""` reference covers everything **except** its own
signature, and a reference to a `ds:Object` covers what it wraps unless the
transforms took it away.

The consequence worth stating plainly: **a whole-document enveloped reference
covers nothing inside the signature it belongs to.** The
`xades:SignedProperties` — which carries the `SigningCertificate` binding — and
the signature's own profile `ds:Object` both live there, so a signature that
relies on `URI=""` alone is `reference_scope_incomplete` and names them. Each
needs a reference of its own, which is what real dossiers write. A reference
whose enveloped transform removes everything it selected is refused outright
(`reference_digest_mismatch`) rather than digested as the empty octet string.

One function decides this, in `references::ReferenceScope`, and the
reference-scope check, the [countersignature binding](#countersignatures) and
the [document coverage](#document-coverage) report all call it, so the three
cannot disagree about what a reference covers. At the binding it matters in one
direction only: the enveloped-signature transform removes the signature the
reference is written in, and an enveloped countersignature sits *inside* the
signature it attests, so its parent's `ds:SignatureValue` is never removed —
but a signature that references a `ds:SignatureValue` nested *within itself*
and then removes itself digests none of it, and binds nothing.

Two further rules follow from what real dossiers actually contain:

- **The signature-profile object is located by content, never by position.**
  The requirement is satisfied by a reference that resolves either to the
  direct `ds:Object` child holding an `es:SignatureProfile` — in any dossier
  namespace the run allows — or to that `es:SignatureProfile` element itself.
  Both spellings occur, and the profile and qualifying-properties objects
  appear in either order, so neither the wrapper nor the child position can be
  assumed.
- **`SignedProperties` coverage is decided by resolution, not by `@Type`.** The
  requirement is satisfied by a reference that resolves to a
  `SignedProperties` element in any recognised XAdES namespace (1.1.1, 1.2.2,
  1.3.2, 1.4.1) or to an ancestor of it. The `Type` attribute is corroboration
  only: an attacker controls it, so it must never be able to satisfy a scope
  requirement on its own. Both `http://uri.etsi.org/01903#SignedProperties` and
  the versioned forms are recognised, and a reference that declares one but
  resolves elsewhere is called out in the failure message, because that is the
  shape a wrapping attempt takes.
- **Any `SignedProperties` the signature owns satisfies it, not the first
  one.** The XMLDSig schema allows a signature any number of `ds:Object`
  children with open content, and nothing obliges a reference to cover a given
  one, so anyone able to append bytes to a dossier can add an
  `xades:SignedProperties` the signer never signed. Requiring the *first* would
  let one such decoy turn a sound signature into `reference_scope_incomplete`
  — and its document into `documents_uncovered` — which is a
  denial-of-verification, not a finding. The elements a countersignature nested
  in this signature owns are still that signature's and satisfy nothing here.
  [Stage C](#xades-signed-properties) reads the same covered element, so what
  the scope rule requires and what the binding is evaluated against cannot
  drift apart.

Where the specification does not define the mandated set — a signature in a
placement the format does not describe, or one inside a `Document` that carries
no `DocumentProfile` — the answer is `reference_scope_unknown` (status
`unknown`), not a guess in either direction.

Every reference's resolved location is reported in
`data.signatures[].references[].resolved_to` as a path of element names, so a
caller can see exactly what was signed without any content leaving the tool.

### Document coverage

Reference scope answers "does this signature cover what it must". Document
coverage answers the other half of the question: **is every document in this
dossier covered by anything at all**. A dossier whose one signature is perfect
and whose second document nothing signs is not a signed dossier, and until
this section existed the tool reported that case as if it were.

`verify` therefore reports, for every `es:Document` in `es:Documents` in source
order, which signatures cover it and how. Coverage is decided by **resolved
references** and the implemented [reference-scope](#reference-scope) rules.
Placement alone never grants coverage: it selects which mandated set applies,
and a signature whose mandated set is incomplete covers nothing, because the
container's own rule for what that signature must reference was not met.

| Route | What grants it |
| --- | --- |
| `direct` | A document-level signature placed in **that** `es:Document`, whose reference scope is complete and whose references resolve to that document's `es:DocumentProfile` and its payload `ds:Object`. |
| `frame` | A dossier-level signature whose reference scope is complete and whose references resolve to `es:Documents`, or to an ancestor of it, so the document sits inside what was signed. |

An element counts as covered when it is inside the [effective node
set](#the-effective-node-set) of one of the signature's references, which is
exactly the rule — and the same code — the scope check applies. A
document-level signature covers only the document it is placed in.

The states, per document:

| State | Meaning |
| --- | --- |
| `covered` | At least one covering signature's own verdict is `valid`. |
| `covered_unverified` | Covered, but only by signatures whose verdict is `invalid` or `indeterminate`. The `reason` names the best verdict among them; those signatures' own entries carry the cryptographic finding. |
| `uncovered` | No signature covers it under the two rules above. |
| `undetermined` | A signature that might cover it could not be evaluated: an unsupported transform or canonicalization algorithm, an unresolved or external reference, a placement the format does not describe, a structural failure, or a signature the run never examined because the dossier is over `max_signatures`. Such a signature clouds the document it sits in, or every document when it sits on the frame. |
| `not_modelled` | The core parser skipped this `es:Document` because it carries no `es:DocumentProfile`, so it is not one of the modelled documents and the mandated set for it is undefined. The `reason` is the parser's own `document_without_profile` warning. |

Coverage is deliberately **separate from the cryptographic outcome**. A
document covered by a signature that does not verify is `covered_unverified`,
not `uncovered`: the content really is inside what that signature references,
and whether the signature holds is a different question, answered by the
signature's own verdict. The reverse holds too: coverage changes no
signature's checks or verdict.

An embedded dossier (`nested_dossier: true`) is payload like any other and is
covered like any other. **Its own inner signatures are not verified by this
run.** There is no implied recursion: `verify` opens no payload, so a covered
embedded dossier means the outer container vouches for those bytes, and says
nothing whatever about the signatures inside them. The report states this on
the document's `reason`.

Three dossier-level checks carry the result, so a caller reading only the
check list still sees it:

- `documents_all_covered` (`passed`) when every modelled document is
  `covered`. It is `info`, not `passed`, when every document is covered but at
  least one only by signatures that did not verify: the finding is already on
  those signatures, and repeating it here would double-count it.
- `documents_uncovered` (`unknown`), naming the count and the indexes.
- `documents_coverage_undetermined` (`unknown`), naming the count.

Both blocking checks are `unknown`, never `failed`. An unsigned sibling is
**missing information about that document**, not evidence against a signature
that did verify, which under ETSI EN 319 102-1 is INDETERMINATE rather than
TOTAL-FAILED. The consequence is the point of the whole section: a dossier
with an unsigned document cannot be `valid`, because a verdict of `valid` has
to mean that the whole dossier's content is signed. Reading a per-signature
`valid` as "this dossier is signed" is precisely the mistake a container
format with sibling documents invites, and the tool must not invite it.

A `not_modelled` document is listed and is in none of the three counts: it is
not a modelled document, the format's mandated set for it is undefined, and
the parser already reports it as a conformance warning.

### Countersignatures

A countersignature signs another signature's `ds:SignatureValue`. It says
"I attest that this signature exists", not "I attest this content", and the
report keeps those apart: a countersignature has a `role`, it names what it
countersigns, and it grants no document coverage whatever.

Two forms reach a dossier, and both are recognised.

**The XAdES enveloped form.** ETSI EN 319 132-1 clause 5.2.7.2 (and ETSI
TS 101903 V1.4.1 clause 7.2.4.2 before it) defines the `CounterSignature`
unsigned qualifying property. Its XML Schema type is a sequence of exactly one
`ds:Signature`, and its content "shall be a XMLDSIG or XAdES signature whose
`ds:SignedInfo` shall contain one `ds:Reference` element referencing the
`ds:SignatureValue` element of the embedding and countersigned XAdES
signature". Clause 5.2.7.1 (TS 101903 clause 7.2.4.1) additionally defines the
`ds:Reference/@Type` value
`http://uri.etsi.org/01903#CountersignedSignature`, whose "only purpose ... is
to serve as an easy identification of a signature as being a
countersignature". This build treats the `Type` exactly that way: as
corroboration. **Resolution decides**, because an attacker writes the
attribute. Such a signature is reported with `placement: "countersignature"`,
`role: "countersignature"`, and `parent_signature_index`.

**The e-dossier form.** The Microsec e-dossier specification describes
countersignatures in its own terms. Clause 3.2.1.3.1 adds to the mandated
reference set of a document-level signature: "In case of a countersign, the
`ds:SignatureValue` element of the countersigned signatures", and the frame
signature's set carries the same addition. Clause 3.2.1.3.4.1.3 gives the
signed `es:SignatureProfile/es:Type` its values: `signature` "signature on a
document or dossier (i.e. not a countersignature)" and `countersignature` "it
is a countersignature", plus the deprecated Hungarian spellings `aláírás` and
`ellenjegyzés` the schema keeps for compatibility. A signature in this form is
an ordinary sibling at a defined placement, so it keeps `placement:
"document"` or `"dossier"` and gains `role: "countersignature"` and
`countersigns`. The declaration is *signed* — the profile object is inside the
mandated reference set — but it still only declares a role; what is actually
attested is decided by what the references resolve to.

Both forms are verified as signatures in their own right: every stage from
structure to revocation applies, unchanged. What countersignatures add is the
binding.

| Code | Status | Meaning |
| --- | --- | --- |
| `countersignature_binding_ok` | `passed` | The countersignature's references resolve to the `ds:SignatureValue` it must attest: for the XAdES form, the signature it is embedded in; for the e-dossier form, at least one other signature's. |
| `countersignature_binding_missing` | `failed` | It does not. A nested signature that binds nothing is not a countersignature of anything, and a profile that declares `countersignature` while referencing no other signature's value contradicts itself. |
| `countersignature_binding_mismatch` | `failed` | A nested signature's reference resolves to a `ds:SignatureValue` other than its lexical parent's. This is the wrapping shape: the element says "I countersign the signature I am inside" and the reference says otherwise. |

`countersigns` lists the indexes of every signature whose `ds:SignatureValue`
this one's references resolve to; a signature never countersigns itself.

**Coverage.** A countersignature covers no document. Document coverage stays
with the signature it attests, and the two `via` routes remain `direct` and
`frame`. This is not an omission: what a countersignature references is a
signature value, and a signature value is not a document.

#### The support boundary

Only the shape above is a countersignature. Everything else nested inside a
`ds:Signature` is **unsupported placement**, and unsupported is deliberately
not a synonym for invalid.

| Shape | Answer |
| --- | --- |
| One `ds:Signature` inside `xades:CounterSignature` inside the enclosing signature's `xades:UnsignedSignatureProperties`, in any recognised XAdES namespace | `placement: "countersignature"` |
| An `xades:CounterSignature` holding two or more `ds:Signature` elements | `unknown`. `CounterSignatureType` is a sequence of exactly one, so two leave two candidate parents and no rule for choosing. |
| A `ds:Signature` nested under anything that is not `xades:UnsignedSignatureProperties/xades:CounterSignature` | `unknown` |

An unsupported nesting produces three things, and no more:

- the nested signature keeps its `sig_placement_invalid` (`failed`) and a
  message that **names the reason**, so its own entry says exactly what
  happened;
- the enclosing signature records `nested_signatures_unsupported` (`info`) and
  its verdict is untouched. It has to be: the enclosing signature does not
  cover its own unsigned properties, so nothing dropped in there can change
  what it says. A dossier where an attacker appends a nested element must not
  become a dossier whose good signature reads as broken;
- the dossier records `signatures_unsupported` (`unknown`), and the nested
  signature's own verdict is **left out of the dossier verdict**.

That last rule is the point of the section. A nesting this build does not
implement is missing support, which under ETSI EN 319 102-1 is INDETERMINATE,
not TOTAL-FAILED. So the dossier is capped at `indeterminate` and never made
`invalid` by an unsupported placement alone. A signature that failed something
*else* as well is folded in as usual, and a binding check that actually fails
is a finding: `countersignature_binding_missing` and
`countersignature_binding_mismatch` make their signature `invalid` and the
dossier with it.

### Algorithm policy

The e-dossier container specification deliberately places no constraint on
canonicalization, digest, or signature algorithms, so this pinned policy is the
only defence against an algorithm downgrade. It is not configurable.

| Kind | Accepted | Refused |
| --- | --- | --- |
| Digest | SHA-256, SHA-384, SHA-512 | SHA-1 by default, MD5 always, and every other URI (`algorithm_rejected`) |
| Signature | RSA PKCS#1 v1.5 and RSA-PSS with SHA-256/384/512 and a modulus of at least 2048 bits; ECDSA P-256 with SHA-256 and P-384 with SHA-384 | RSA-SHA1 by default; MD5 variants, DSA, every HMAC method, RSA below 2048 bits, and a curve that does not match the named digest always (`algorithm_rejected`) |
| Canonicalization | Canonical XML 1.0 and Exclusive XML Canonicalization 1.0, each with and without comments | Canonical XML 1.1 and anything else (`c14n_unsupported`) |
| Transform | enveloped-signature, the four canonicalization algorithms above, and base64 | XSLT, XPath, XPath Filter 2.0, and anything else (`transform_not_allowed`) |

XSLT and XPath are refused unconditionally: they turn a reference into an
arbitrary computation over the document, which is the transform-abuse threat
this project refuses rather than bounds. An HMAC `SignatureMethod` in a dossier
is a known attack shape and is refused outright, which removes the
`HMACOutputLength` truncation class with it. Canonical XML 1.1 is refused
rather than approximated with 1.0, because the two differ on `xml:base` and on
`xml:*` attribute inheritance; refusing to answer is acceptable, answering
wrongly is not.

`--allow-legacy-algorithms` admits SHA-1 digests and the RSA-SHA1 signature
method **for diagnosis only**, which matters because Hungarian dossiers span
2007 to today and older material genuinely uses SHA-1. Under the flag those
algorithms emit `algorithm_legacy_allowed` with status `unknown` rather than
`digest_algorithm_allowed`/`signature_algorithm_allowed` with status `passed`,
so the verdict is capped at `indeterminate` and the tool never vouches for the
algorithm's strength. The status is `unknown` because the check-status
vocabulary has no separate "warning" value and `unknown` is the honest reading:
the digests were recomputed and matched, and the tool cannot say whether that
means anything. The flag can only ever lower a verdict: a `failed` check is
never turned into a `passed` one, and MD5, DSA, every HMAC method, and RSA keys
below 2048 bits stay refused whatever it is set to. It does not loosen
certificate-path validation either — a SHA-1-signed certificate is still
`cert_algorithm_rejected`.

Canonicalization is implemented in-tree, over the same `roxmltree` tree the
structural parser built, rather than delegated. The candidate library named in
the design (`bergshamra-c14n`) canonicalizes its own parser's tree and selects
document subsets by that tree's node indices, so using it would mean parsing
every dossier a second time with a second parser and trusting the two trees to
agree. It sits behind the `C14nBackend` trait, so a differential backend can
be added without touching the pipeline.

### Verification limits

Reported verbatim under `data.limits` in `verify --json`.

| Limit | Default | Purpose |
| --- | --- | --- |
| `max_signatures` | 64 | `ds:Signature` elements examined per dossier. |
| `max_references_per_signature` | 32 | `ds:Reference` elements per signature. |
| `max_transforms_per_reference` | 8 | Transforms in one reference's chain. |
| `max_certificates` | 64 | Certificates admitted into path building. |
| `max_timestamps_per_signature` | 8 | `xades:SignatureTimeStamp` elements processed per signature. |
| `max_chain_length` | 8 | Certificates in one candidate path, inclusive: a path of exactly this many certificates that ends at an anchor is accepted. |
| `max_paths` | 32 | Completed candidate paths explored. |
| `max_revocation_items` | 256 | CRLs or OCSP responses consulted from any one source while answering about a single certificate. |
| path search expansions | 256 (fixed) | Total candidates visited during path building, successful or not. Not configurable. |
| `ds:KeyInfo` candidates | 16 (fixed) | Certificates tried as the signer. |
| `xades:Cert` entries | 16 (fixed) | `SigningCertificate` entries digested against the candidates. |
| timestamp token size | 512 KiB (fixed) | Largest RFC 3161 token parsed. |

### Signing-certificate selection

XMLDSig places no order on `ds:KeyInfo`, and real material does list an issuer
before the signer, so taking the first `ds:X509Certificate` would turn a good
signature into a false failure. Instead every certificate in `ds:KeyInfo` (at
most 16) is a candidate, and the signing certificate is the one whose public
key actually verifies `ds:SignatureValue`. End-entity certificates are tried
before CAs so the common case costs one verification.
`signatures[].signing_certificate_index` reports which candidate was chosen,
counted from zero in document order, and is `null` when none verified — in
which case `signature_value_invalid` says how many were tried. A candidate with
a key below the minimum size or of an unsupported type is reported as
`algorithm_rejected` rather than as a mismatch.

The key-based selection is only the fallback. When the signature carries a
signed `SigningCertificate` property, **that property decides**, and a
disagreement is a failure rather than a preference: see below.

### XAdES signed properties

`ds:KeyInfo` is unsigned unless a reference happens to cover it, so on its own
it is a hint from whoever assembled the file. The XAdES
`SigningCertificate` (XAdES 1.3.2 and earlier) and `SigningCertificateV2`
(EN 319 132-1) properties live inside `xades:SignedProperties`, which the
mandated reference set requires the signature to cover, so what they say is
signed. `verify` therefore treats the certificate their `CertDigest` names as
the certificate the signature claims, in every recognised XAdES namespace
(1.1.1, 1.2.2, 1.3.2, 1.4.1).

**Which properties, though, is itself decided by coverage.** A `ds:Object` is
open content: the schema allows any number of them under a `ds:Signature` and
nothing requires a reference to cover one, so an inserted decoy object can hold
a whole `xades:QualifyingProperties` the signer never signed. The properties
stage C reads are therefore the ones a reference of *this* signature actually
digests — the `xades:SignedProperties` that lies inside one reference's
[effective node set](#the-effective-node-set), and the
`xades:QualifyingProperties` holding it — never simply the first such element
in document order. The `Type` attribute
`http://uri.etsi.org/01903#SignedProperties` is corroboration, exactly as it is
in the scope rule, and never the rule itself. Three consequences:

- when no reference of the signature covers any `SignedProperties`, nothing
  there is signed: the signed properties are treated as absent and the binding
  reports `xades_signing_certificate_absent` rather than believing an unsigned
  property. Such a signature also fails `reference_scope_incomplete` whenever
  the mandated set is defined;
- when more than one `xades:QualifyingProperties` belongs to one signature,
  covered or not, it is said once as `xades_extra_qualifying_properties`
  (`info`) and the uncovered ones are ignored. Informational on purpose:
  blocking would hand anyone who can append a `ds:Object` the power to cap a
  sound signature at `indeterminate`, which is the same lever this rule closes;
- a countersignature's qualifying properties belong to the countersignature.
  The signature they are nested in never reads them, and they never satisfy its
  requirements.

A `Target` attribute that names another signature is reported as it always was
and decides nothing: coverage is the rule.

The rules:

- the digest is recomputed over the DER of each offered certificate with the
  algorithm the property declares, which must be inside the pinned digest
  allowlist; SHA-1 is refused unless `--allow-legacy-algorithms` is given, and
  then it still cannot produce a `passed`;
- when `IssuerSerialV2` is present its DER issuer name and serial must match
  the digested certificate exactly. For the older `IssuerSerial`, only the
  serial number is compared: its issuer is an RFC 4514 string, and comparing
  that to a DER name needs name preparation this project does not implement.
  The digest is the binding; issuer and serial are corroboration, and a
  corroboration that contradicts the digest fails;
- **if the certificate whose key verified `ds:SignatureValue` is not the
  digested one, the signature fails** with
  `xades_signing_certificate_mismatch`, and the certificate reported and
  path-validated is the one the signed property designates. This is the
  certificate-substitution check;
- a signature carrying no such property emits
  `xades_signing_certificate_absent` with status `unknown`: nothing signed says
  which certificate signed it.

`SignaturePolicyIdentifier` is reported and never applied:
`xades_signature_policy_implied` or `xades_signature_policy_explicit`, both
`unknown`, with the explicit form's identifier in
`signatures[].xades.signature_policy_id`. No policy document is fetched,
parsed, or enforced. Any other qualifying property — `CompleteCertificateRefs`,
`RevocationValues`, `SignerRole`, `DataObjectFormat`, and the rest — is named
in `signatures[].xades.unvalidated_properties` and reported once as
`xades_not_validated`. `ArchiveTimeStamp` gets its own
`archive_timestamp_present`, `skipped`: it covers a much larger,
version-dependent set of data and is out of scope.

### Signature timestamps

Each `xades:SignatureTimeStamp` in the unsigned properties carries an RFC 3161
token in an `xades:EncapsulatedTimeStamp`. Each token is verified in this
order, and every step must pass before the token counts as verified:

| Step | Check code | What it means |
| --- | --- | --- |
| 1 | `timestamp_token_parsed` | The token is a CMS `SignedData` whose encapsulated content type is `id-ct-TSTInfo` and whose `TSTInfo` decodes. |
| 2 | `timestamp_imprint_ok` | `messageImprint` equals the digest of the canonicalized `ds:SignatureValue`, under an allowlisted algorithm. |
| 3 | `timestamp_signature_ok` | The `SignerInfo` signature verifies over the DER `SET OF` encoding of the signed attributes, whose `content-type` is `id-ct-TSTInfo` and whose `message-digest` matches the eContent. |
| 4 | `timestamp_tsa_certificate_ok` | The TSA certificate carries `extendedKeyUsage` with `id-kp-timeStamping` and nothing else, marked critical (RFC 3161 section 2.3). |
| 5 | `timestamp_tsa_path_ok` | That certificate chains to a configured anchor **at `genTime`**, because a timestamp asserts existence at that instant. |

The TSA path is built from the union of the token's own `SignedData`
certificates, the enclosing signature's `ds:KeyInfo` and
`xades:CertificateValues` candidates, and the trust store's intermediates,
deduplicated by DER. Real dossiers put the TSA's issuing CA in the
*signature's* `CertificateValues` and only the TSA leaf inside the token, so a
verifier that looked in the token alone would report a chain break that is not
there. Anchors still come from the trust store alone.

A `xades:SignatureTimeStamp` covers the canonicalized `ds:SignatureValue`
**element** — start tag, content, end tag — not the Base64 text and not its
digest. The algorithm is the one the timestamp's own
`ds:CanonicalizationMethod` names, defaulting to inclusive C14N 1.0 as XAdES
prescribes.

Two container shapes are accepted. XAdES prescribes a bare RFC 3161
`TimeStampToken`, which is a CMS `ContentInfo`; producers of the XAdES 1.2.2
era instead embedded the entire `TimeStampResp` — `SEQUENCE { status
PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }` — and those dossiers
still have to verify. A `TimeStampResp` is unwrapped only when its `PKIStatus`
is `granted` (0) or `grantedWithMods` (1); any other status, or a response with
no token, is `timestamp_token_parsed` (`failed`) with the status named, because
reading the token field of a rejection would turn a refusal into a
verification. DER that is neither shape fails with its outermost tag named,
which is public information and the one thing that makes the failure
actionable.

Data selection comes in two forms. The **implicit** form has no selection
child at all and means the `ds:SignatureValue` element. The **explicit**
`xades:Include` form (EN 319 132-1, XAdES 1.3.2 and 1.4.1) is accepted for
exactly the case where it says the same thing: every `Include` is a
same-document `#id` reference resolving, through the validated ID space, to
this signature's own `ds:SignatureValue`. Several such `Include` elements are
equivalent to one. The `referencedData` attribute is not consulted, because for
this target it cannot change what is digested.

Everything else is reported as `timestamp_not_checked` (`skipped`) rather than
digested over bytes the timestamp did not mean: an `Include` naming any other
element or failing to resolve, the `ReferenceInfo`, `HashDataInfo` and
`XMLTimeStamp` forms, a timestamp with no decodable token or with more than
one, and one naming a canonicalization algorithm this build does not
implement.

`timestamp_verified` summarises one token inside the signature's own check
list: `passed` when every step passed, and **`unknown` otherwise — never
`failed`**. The token keeps its own `failed` checks; see
[Verdicts](#verdicts) for why the summary does not.

Per signature, `signature_timestamp_present` or
`signature_timestamp_absent` is emitted, always `unknown`, because a timestamp
proves existence and not validity.

`timestamp_before_signing_time` is `unknown`, never `failed`: when a token's
`genTime` is earlier than the claimed `xades:SigningTime` by more than the
token's declared accuracy, the two contradict each other, but `SigningTime` is
an unauthenticated claim and a claim cannot condemn a verified token.

Dossier-level and document-level `es:TimeStamp` elements protect the elements
they reference; see [Container timestamps](#container-timestamps).

### Container timestamps

An `es:TimeStamp` is not a signature timestamp. The e-dossier specification
gives it `xades:TimeStampType` semantics, so it protects **the elements its
`xades:Include` children name**, and unlike a `SignatureTimeStamp` it has no
implicit data selection to fall back on. Verifying one needs the reference
resolution, the scope rule and the canonicalization a signature gets, which is
what M3 added.

| Step | What is required |
| --- | --- |
| Placement | A direct `es:TimeStamp` child of `es:Dossier` is a **dossier timestamp**; a direct child of `es:Document` is a **document timestamp**. Anywhere else, the format does not say what the element protects and nothing is digested. |
| Resolution | Every `xades:Include/@URI` is `#id` and must resolve, through the ID space `openszigno-core` validated, to exactly one element. Nothing is ever dereferenced off the document. |
| Scope | A dossier timestamp must cover `/es:Dossier/es:DossierProfile` **and** `/es:Dossier/es:Documents`. A document timestamp must cover its `es:DocumentProfile` **and** the document's payload `ds:Object`. An element is covered when an `Include` resolves to it or to an ancestor of it. |
| Imprint | Each included element is canonicalized on its own with the algorithm the timestamp's `ds:CanonicalizationMethod` names — inclusive C14N 1.0 when it names none, as XAdES 7.1.4.3.1 prescribes — and the results are concatenated **in `Include` document order**. Reordering the `Include` elements changes the imprint, which is the point. |
| Token | Verified by exactly the machinery a signature timestamp uses: the CMS parse, the imprint, the `SignerInfo` signature, the critical `id-kp-timeStamping` requirement, and a TSA path validated at `genTime`. |

The scope rule matters for the same reason it does on a signature: without it,
a timestamp that covers only the payload would attest to a document whose
profile — its title, its declared type — could still be rewritten afterwards.

**What a container timestamp decides.** Nothing about any signature. It is a
statement about the container, so it is reported at the dossier level and is
never folded into a signature's checks or verdict; a dossier that carries one
produces exactly the same per-signature output as one that does not. It can
lower the **dossier** verdict, and only in one direction:

- `dossier_timestamp_invalid` / `document_timestamp_invalid` (**`failed`**)
  when the token is evidence *against* the container: the imprint does not
  match the elements it names, the token will not parse, the TSA's signature
  does not verify, or the TSA certificate is not a timestamping certificate.
  The dossier verdict becomes `invalid` while every signature keeps the verdict
  its own evidence earned, and the JSON keeps the two apart.
- `dossier_timestamp_verified` / `document_timestamp_verified` (`info`) when
  every check on the token passed.
- `dossier_timestamp_not_checked` / `document_timestamp_not_checked` (`info`)
  for everything else, which is a gap in the caller's material rather than a
  finding: no trust anchors were configured, an `Include` did not resolve, the
  mandated elements are not covered, the data selection uses a form this build
  does not implement (`ReferenceInfo`, `HashDataInfo`, `XMLTimeStamp`, or no
  `Include` at all), the token would not decode, or there is more than one.
  Informational, because carrying more evidence than the minimum must never
  make a dossier look worse than carrying none.

Each container timestamp appears in `data.timestamps[]` with its own `checks`,
its `kind` (`dossier-timestamp` or `document-timestamp`), and, for a document
timestamp, the `document_index` it belongs to. `data.counts.timestamps` counts
them and `data.counts.timestamps_verified` counts the ones that verified
completely.

### Archive timestamps

`xades:ArchiveTimeStamp` — the XAdES-A / B-LTA element, in both the 1.3.2 and
the `xadesv141` spelling — is still reported as `archive_timestamp_present`
(`info`) and **is not verified**. This is a deliberate M3 decision, not an
oversight, and the reason is worth stating plainly.

The XAdES 1.4.1 clause 8.2.1 imprint is an ordered concatenation of the
references' processed data, `ds:SignedInfo`, `ds:SignatureValue`,
`ds:KeyInfo`, the unsigned qualifying properties in order, and the `ds:Object`
elements. Several parts of that ordering are under-specified in ways that only
interoperability testing can settle: which namespace context each unsigned
property is canonicalized in, how properties added *after* the archive
timestamp are excluded, whether the `ds:Object` holding the qualifying
properties participates, and how the 1.3.2 and 1.4.1 forms differ in all three.
This project has no real-world archive-timestamped material to check an
implementation against, and a synthetic fixture generated by the same code that
verifies it proves nothing at all — it would only assert that the
implementation agrees with itself.

Reporting `archive_timestamp_verified` on that basis would be exactly the kind
of unearned assurance this project refuses. So the element is named, counted in
`xades.archive_timestamps`, and left unverified; no `poe_times` are recorded
and an archive timestamp does not extend the validation-time reasoning. A
`valid` verdict continues to say that the signature's own evidence checks out
at the stated validation time, not that its archival chain does. Closing this
needs consented real B-LTA material or a second implementation to differ
against; it is tracked as a residual in [roadmap.md](roadmap.md).

### Validation time

Each signature's certificate path is validated at that signature's own
validation time, reported as `signatures[].validation_time` with
`signatures[].validation_time_source`. The precedence is fixed:

| Source | When it applies |
| --- | --- |
| `at_flag` | `--at` was given. An operator asking "was this valid then?" must not be answered about some other instant, so `--at` always wins. |
| `timestamp` | No `--at`, and at least one signature timestamp verified completely. The earliest such `genTime` is used. |
| `current_time` | Neither of the above. |

This is what lets a historical dossier chain: a signing certificate that
expired years ago was valid at the timestamp's `genTime`, and a verified
timestamp is proof that the signature existed then. A token that did not fully
verify — including one whose TSA chain is `unknown` because no trust store was
configured — never moves the validation time.

`data.verification_time` at the top of the report keeps its meaning: the `--at`
value and the clock reading for the run as a whole, not the per-signature
result.

### Where candidate certificates come from

| Source | `chain[].source` | Role |
| --- | --- | --- |
| `ds:KeyInfo/ds:X509Data/ds:X509Certificate` | `key_info` | Signing-certificate candidates, and untrusted path candidates. |
| `xades:CertificateValues/xades:EncapsulatedX509Certificate`, and any other encapsulated certificate under the signature's XAdES properties | `certificate_values` | Untrusted path candidates. This is where real dossiers carry the intermediates, and usually the root. |
| A non-self-signed file in the trust store | `trust_store` | Untrusted path candidate. |
| A self-signed file in the trust store | `trust_store` | **Trust anchor.** |
| The `certificates` set of an RFC 3161 token | `timestamp_token` | Untrusted path candidates for that token's TSA certificate. The signature's own candidates and the store's intermediates are offered alongside them, because real dossiers carry the TSA's issuing CA in `xades:CertificateValues`. |

The rule that matters: **only the trust store can supply an anchor.** A
self-signed root found inside a dossier is a candidate like any other and can
never make itself trusted; a dossier that carries its own root and no store is
configured still reports `cert_path_unknown`. Candidates are deduplicated by
DER, keeping the source they were first seen in, and a certificate the store
already anchors is used only in that role, so it cannot appear twice in one
path.

### Certificate path validation

There is no general-purpose RFC 5280 path validator in Rust that fits eIDAS
signing certificates — `rustls-webpki` is Web-PKI shaped and wants a DNS name —
so this is hand-written on `x509-cert`. That is a liability, and the mitigation
is a narrow, explicitly documented subset plus heavy negative testing. The
implemented subset is:

- candidate paths built by matching the subject distinguished name of a
  candidate issuer to the issuer name of the certificate below it, comparing
  the DER encodings (no RFC 4518 string preparation), bounded by
  `max_chain_length`, `max_paths`, **and a hard budget of 256 total search
  expansions**. The first two bounds are not enough on their own: a bag of
  certificates whose names all match but which never reaches an anchor produces
  no completed paths at all while the search explores exponentially many
  prefixes. Exceeding the budget is the distinct outcome
  `cert_path_search_exhausted`, reported as `unknown` — the tool stopped
  looking, which is not the same statement as "no path exists", and giving up
  must not read as a finding against the signature;
- completion checked before the length bound, so a chain of exactly
  `max_chain_length` certificates that reaches an anchor is a path rather than
  one the search refused to look at;
- every link's signature verified with the issuer's public key under the
  algorithm allowlist above;
- every certificate's validity window checked against the validation time;
- `basicConstraints` with `cA=true` required on every non-leaf, and
  `pathLenConstraint` compliance checked against the number of intermediates
  below it;
- `keyUsage` `keyCertSign` required on any non-leaf that declares the
  extension, and `digitalSignature` or `nonRepudiation` on a leaf that declares
  it; an absent `keyUsage` does not by itself fail a certificate;
- `nameConstraints`, when present on a CA, applied to every certificate below
  it, per RFC 5280 section 4.2.1.10 and **failing closed throughout** (see
  below);
- critical extensions handled as below.

**Name constraints.** `directoryName` subtrees match as an RDN-sequence prefix
of the subject. `dNSName` subtrees match a host exactly or on a label boundary,
so `example.com` covers `host.example.com` but never `notexample.com`; a
leading dot means subdomains only. `rfc822Name` subtrees match an exact mailbox
when the constraint has a local part, the exact host part when it does not, and
any mailbox at or below the domain when it starts with a dot.
`uniformResourceIdentifier` subtrees are matched **against the URI's host**,
extracted from the authority, using the same label rules — a substring match
would let `https://evil.test/example.com` satisfy `example.com`. A URI with no
host, or whose host is an IP literal, cannot satisfy a DNS-style constraint and
is a violation rather than a pass. `iPAddress` subtrees are evaluated as an
address and mask of equal width. Every remaining case fails closed: a
constraint form this validator does not implement, a `minimum`/`maximum`
distance (which RFC 5280 forbids anyway), a name form it cannot evaluate under
a constrained CA, and a permitted subtree of a type the certificate carries but
does not match are all `cert_name_constraint_violation`.

**Critical extensions.** RFC 5280 requires a verifier to reject a certificate
carrying a critical extension it does not process, so the accepted set is
exactly what is processed: `basicConstraints`, `keyUsage`, `nameConstraints`,
`subjectAltName`, and `extendedKeyUsage`. Anything else marked critical is
`cert_unsupported_critical_extension`, including `certificatePolicies` (policy
processing is not implemented), QCStatements, `cRLDistributionPoints`, and
`authorityInfoAccess` — all of which are non-critical in practice, so marking
one critical is a request for processing this tool cannot honour.

**Extended key usage.** RFC 5280 section 4.2.1.12 makes `extendedKeyUsage` a
restriction on what the key may be used for **whether or not the extension is
critical**, so criticality does not decide whether it is enforced on the
end-entity certificate. An absent extension imposes no restriction and is
accepted; a present one must name a purpose that covers this use:

| Purpose | Accepted for a signing certificate | Accepted for a TSA certificate |
| --- | --- | --- |
| absent | yes | no — RFC 3161 requires the extension |
| `anyExtendedKeyUsage` (2.5.29.37.0) | yes | no — RFC 3161 wants exactly `id-kp-timeStamping` |
| `id-kp-documentSigning` (1.3.6.1.5.5.7.3.36, RFC 9336) | yes | no |
| `szOID_KP_DOCUMENT_SIGNING` (1.3.6.1.4.1.311.10.3.12) | yes | no |
| `id-kp-timeStamping` (1.3.6.1.5.5.7.3.8) | see below | required, alone and critical |
| `id-kp-emailProtection`, `serverAuth`, `clientAuth`, `codeSigning`, `OCSPSigning` | see below | no |

`szOID_KP_DOCUMENT_SIGNING` is Microsoft's "Document Signing" purpose from its
private arc. It predates RFC 9336 by two decades and is what European
qualified-signature CAs actually put in signing certificates, so it is accepted
for the same purpose as the RFC's own OID.

An `extendedKeyUsage` that names none of the accepted purposes does not
automatically refuse the certificate. ETSI EN 319 412-2 makes `nonRepudiation`
(`contentCommitment`) *the* key-usage signal for a signing certificate, and
real qualified certificates pair it with an `extendedKeyUsage` that says
`emailProtection` and nothing else. Calling those signatures invalid over a
purpose field the issuer filled in loosely would be wrong, so:

| `keyUsage` | `extendedKeyUsage` | Outcome |
| --- | --- | --- |
| `nonRepudiation` (with or without `digitalSignature`) | absent, or naming an accepted purpose | `cert_path_ok`, no caveat |
| `nonRepudiation` | present, naming only unrelated purposes | `cert_key_usage_advisory` (`unknown`), naming the OIDs found; the path still passes and the verdict is capped at `indeterminate` |
| `digitalSignature` only | present, naming only unrelated purposes | `cert_key_usage_invalid` (`failed`) — nothing signals a signing certificate |
| neither `digitalSignature` nor `nonRepudiation` | anything | `cert_key_usage_invalid` (`failed`) — the key was not issued to sign |

A **CA** certificate's `extendedKeyUsage` is enforced only when it is marked
critical: RFC 5280 gives no path-processing rule for EKU in a CA certificate,
real eIDAS hierarchies carry advisory sets there, and refusing them would
reject chains that are correct — but a CA that marks the extension critical has
asked to be taken at its word, and is. There is no advisory downgrade for a CA
or for a TSA certificate.

**Malformed is not absent.** An extension whose bytes do not decode as its OID
says they should is `cert_malformed` (failed). Treating a decoding failure as
absence would make a corrupt `keyUsage` or `nameConstraints` silently vanish,
which is the wrong direction for every one of them.

Not implemented: authority/subject key identifier matching as a path
hint, certificate policies and `policyConstraints`, `inhibitAnyPolicy`,
qualified-status determination, and cross-certificate handling beyond what
plain name chaining gives.

With no trust store configured, the path check is `cert_path_unknown` with
status `unknown` — not `failed`. The tool does not know, and saying "invalid"
would be as wrong as saying "valid".

### Trust store

`--trust-store DIR` reads certificates from a directory:

```text
<dir>/anchors/*        trust anchors, PEM or DER, one or more certs per file
<dir>/intermediates/*  optional extra CA certificates for path building
```

A directory holding certificate files directly, with no `anchors`
subdirectory, is read the same way. The split between the two subdirectories is
a convention, not a grant: **the verifier classifies what it is given**, and a
certificate is a trust anchor if and only if it is self-signed. Dropping an
intermediate into `anchors/` therefore makes it an extra untrusted path
candidate, not a trusted one, and a store holding only intermediates yields no
anchors and so `cert_path_unknown`. A self-signed anchor's own signature is
deliberately not verified: RFC 5280 does not require it, and demanding it would
reject a legitimate root that signed itself with an algorithm outside this
tool's allowlist. The classification never grants trust on its own — nothing
found inside a dossier is ever an anchor, however it is signed.

Files are read in sorted order so the same store always builds the same paths;
subdirectories and symlinks are skipped rather than followed, and a symlink is
refused by the open itself (see [Bounded file reads](#bounded-file-reads)).
**Every entry is parsed as an X.509 certificate at load time**, so a store that
loads is one whose every byte was understood: one malformed entry among good
ones fails the whole store. A file above 4 MiB, a directory holding more than
1024 entries, an entry that is not a valid certificate, and an empty store are
all `trust_store_invalid` (exit 3), and the message names the entry's ordinal,
never the file, because the path may be private. No trust anchors are compiled
into the binary.

### Trusted lists

`--trust-list FILE`, repeatable, loads an ETSI TS 119 612 trusted list. The
combined anchor set is the union of the `--trust-store` anchors and the
trusted-list ones, and each anchor is reported with its origin in the chain
entry's `trust_anchor_origin` (`trust_store` or `trust_list`).

A trusted list gives what a directory of certificates cannot: **when** each CA
was entitled to issue qualified certificates. For every `TSPService` of type
`.../Svctype/CA/QC` or `.../Svctype/TSA/QTST`, each `X509Certificate` in the
service digital identity becomes an anchor carrying the service's status
timeline — the current `ServiceStatus` and `StatusStartingTime` plus every
`ServiceHistoryInstance`. The status in force **at the validation time**
decides, which is what lets a signature made while a CA was supervised still
verify after that CA was withdrawn.

`granted` and `recognisedatnationallevel` count as granted at any time. The
pre-eIDAS statuses `undersupervision` and `accredited` count only at a
validation time before 2016-07-01, when eIDAS began to apply; every terminal
status (`withdrawn`, `supervisionceased`, the `deprecated*` family) never does.
See [Trusted lists](trust.md#what-is-read-and-what-is-not) for why the
pre-eIDAS window is closed rather than open-ended.

#### A path may only end at a service that was granted then

When a built and validated path ends at a **trusted-list** anchor, that
anchor's service record is consulted before the path is accepted:

| The list records, for this certificate | Then |
| --- | --- |
| A service of the kind the path needs — CA/QC for a signing or OCSP-signing path, TSA/QTST for a timestamping one — granted at the validation time | The path ends here: `cert_path_ok`. |
| A service of that kind that was **not** granted then | `trust_list_service_not_granted` (`unknown`). The search carries on to the other candidate paths first, because another anchor may still be entitled to end one. |
| Only services of some *other* kind, at least one of them granted then | The list has said nothing about this use, so the anchor is treated as a trust-store one would be and the path ends here. A national list that names a root under its CA/QC services and nowhere else still vouches for that root when a timestamp authority beneath it is checked. |
| Only services none of which was granted then | `trust_list_service_not_granted`. The list has stopped vouching for the certificate altogether. |

A `--trust-store` anchor is unaffected: the operator put the file in the
directory, and that is the whole of the statement. When the same certificate
arrives both ways, the trust store's unconditional statement stands.

`trust_list_service_not_granted` is **`unknown`, never `failed`**. Trust that
is missing is not evidence against a signature: the same distinction
`cert_path_unknown` draws. It blocks, so the verdict is capped at
`indeterminate`, and it never makes a run `invalid`. The chain is still
reported in full, and so is the qualified determination, because a reader
needs to see *which* anchor was refused and under which service.

For a timestamp the same check runs at the token's `genTime` against the
TSA/QTST service type, and the code is reported in place of
`timestamp_tsa_path_ok`, again as `unknown`.

`--trust-list-signer CERT` supplies the certificate the list must have been
signed with, obtained out of band — for the EU list of trusted lists, from the
Official Journal. The list's enveloped XMLDSig signature is then verified with
the same core, the same canonicalization backend, and the same pinned
allowlists a dossier gets, and it must cover the whole document. Without it,
and without `--lotl`, the list is still read but `trust_list_unverified`
(`unknown`) is emitted, so the run can never reach `valid`. Nothing is fetched;
`docs/trust.md` describes the manual download workflow.

`--lotl FILE` reads the EU list of trusted lists. Its `PointersToOtherTSL`
entries name the signing certificates of the national lists, so **one**
out-of-band certificate bootstraps the verification of every `--trust-list`:
the LOTL is verified against `--trust-list-signer` first, and only then are its
pointer certificates added to the pool each national list's signature is tried
against. Any one of them verifying is enough, because a scheme operator may
publish several and a verifier cannot know which signed the copy in hand. The
LOTL contributes no trust anchors of its own — it names no CA/QC services — and
its own `trust_list_unverified` check still blocks when it could not be
verified, so pointers taken from an unverified LOTL cannot quietly support a
`valid` verdict.

A `--trust-list` file that is not a trusted list, or a `--trust-list-signer`
file that is not exactly one certificate, is `trust_list_invalid` (exit 3).

#### Qualified status

`qualified` is reported per signature, mirrored onto
`signing_certificate.qualified`, and accompanied by `qualified_service`, the
name of the trusted-list service that decided it.

**The determination is made over the whole validated chain, not over its
anchor.** In a real trusted list the CA/QC service identities are the *issuing*
CAs, which are intermediates; the root above them is often present only in a
`--trust-store` directory and is sometimes not listed at all. Asking only the
anchor reports "not determined" for precisely the chains a trusted list exists
to describe.

So `qualified` is `true` when both of these hold:

1. some certificate in the validated chain **is**, or was **issued by**, the
   service digital identity of a CA/QC service the list records as granted at
   the validation time. "Issued by" is a verified signature, not a name match,
   so a certificate that merely claims a listed issuer gains nothing; and
2. the signing certificate's own `QCStatements` do not contradict that. A
   certificate issued on or after 2016-07-01, when eIDAS began to apply, whose
   `qcStatements` extension is **present but omits** `QcCompliance`
   (`0.4.0.1862.1.1`), or which will not parse, contradicts the list and yields
   `false`.

A post-eIDAS certificate carrying **no** `qcStatements` extension at all denies
nothing, and the determination rests on the trusted list alone, exactly as it
does for a pre-eIDAS certificate. That is the looser of the two readings and it
is deliberate: the trusted list is the authority on which CA may issue
qualified certificates, and an issuer that omitted an assertion has not denied
it.

`qualified_signature_device` reports the `QcSSCD`/QSCD statement
(`0.4.0.1862.1.4`) separately. Both are the issuer's claims, which only a
trusted list makes meaningful.

The value is `null`, never `false`, when no trusted list was consulted at all;
`false` when one was and nothing in the chain is covered by a granted CA/QC
service. "Not determined" and "determined not to be qualified" are different
answers and the report keeps them apart. The three outcomes are reported as
`certificate_qualified`, `certificate_not_qualified`, and
`certificate_qualified_unknown`, all `info`, because they describe a legal
category rather than the cryptographic soundness of the signature.

When the same certificate is both a `--trust-store` anchor and a trusted-list
service identity, `trust_anchor_origin` reports `trust_list`: the list is the
stronger provenance, because it says *who* vouches for the CA where a directory
only says that somebody copied it in.

Scheme-level `Qualifications` extensions, which refine qualified status per
certificate subset, are not processed and are never used to widen a
determination.

### Revocation

Offline by default and offline only. **Every source is asked about every
certificate, and the answers are then weighed** ([Which answer
wins](#which-answer-wins)). The order below is the order sources are *read*
in; it never decides which answer is believed:

1. the signature's own validation data — `EncapsulatedOCSPValue`, then
   `EncapsulatedCRLValue` — from **either** placement: directly under
   `xades:UnsignedSignatureProperties/xades:RevocationValues`, or inside an
   `xades141:TimeStampValidationData`. Real long-term Microsec dossiers file
   almost all of their embedded OCSP responses in the second, so a verifier
   that reads only the first finds nothing in most real material. The container
   is matched in any recognised XAdES namespace and the encapsulating elements
   inside it by name alone, because real dossiers nest 1.3.2-namespaced values
   under a 1.4.1-namespaced container. `xades:CertificateValues` is harvested
   from both placements too;
2. `--revocation-store DIR`, whose OCSP responses are asked before its CRLs.

Whether a blob was filed as signature validation data or as timestamp
validation data changes nothing about how it is treated: every item is
untrusted input that must be signature-checked against an authorised issuer, so
gathering both can only widen what is *available*, never what is accepted.

Embedded data is **untrusted input**, exactly like the certificates in
`CertificateValues`: the signer supplied it. Every item is signature-checked
against an authorised issuer before anything in it is believed, because taking
it at face value would let a signer prove its own certificate was never
revoked.

`--revocation-store DIR` reads `crls/` and `ocsp/`, or a flat directory,
classifying every file by what it actually contains. A file that is neither a
CRL nor an OCSP response is `revocation_store_invalid` (exit 3): "no revocation
data" is itself a verdict-affecting answer, so a store that quietly dropped
half its contents would be worse than no store at all.

**CRLs**, per RFC 5280 section 6.3: the CRL `issuer` must equal the
certificate's `issuer`; the signature must verify under the pinned allowlist
against the issuing CA or against a delegate that CA issued whose subject is
the CRL issuer and which asserts `cRLSign`; the scope must cover the
certificate. Fail-closed on everything else — a delta CRL, an indirect CRL, an
`issuingDistributionPoint` restricted to reasons or attribute certificates, one
scoped to CA certificates when the target is an end-entity certificate (or the
reverse), a partitioned CRL naming a distribution point the certificate does
not, a `distributionPoint` given as a name relative to the CRL issuer, an entry
carrying `certificateIssuer`, and any critical CRL extension other than
`issuingDistributionPoint`. `certificateHold` counts as revoked: a suspended
certificate is not a usable one.

**OCSP**, per RFC 6960: the `OCSPResponseStatus` must be `successful`; the
`certID` must match the certificate, by issuer-name hash, issuer-key hash and
serial number; the responder must be **authorised** (below); and the signature
must verify under the pinned allowlist. The nonce is deliberately ignored:
offline validation replays a response produced for someone else's request, so a
nonce could never match and demanding one would make every archived response
unusable.

#### How a responder is authorised

RFC 6960 section 2.2 gives a relying party three ways to accept a response, and
openSzigno implements all three under a fixed precedence. Whichever one applied
is reported in `chain[].revocation.responder_model`.

| Model | What it requires | Where the authority comes from |
| --- | --- | --- |
| `issuer` | The CA that issued the queried certificate signed the response itself. | The CA. |
| `delegated` | A certificate that same CA issued, naming itself in the `ResponderID`, carrying `id-kp-OCSPSigning` and valid at the validation time, signed it. | The CA's signature over the responder certificate *is* the delegation, so no trust store is needed. |
| `trusted` | The responder carries `id-kp-OCSPSigning` and its own path validates to a **configured trust anchor** — trust store or trusted list — at the response's `producedAt`, under the same path rules and `keyUsage` checks every other chain gets. | The caller's own trust material. |

The third model is not a relaxation of the first two; it is the third thing
RFC 6960 has always allowed, and real hierarchies need it. A national CA
operator commonly runs **one** responder for every CA it operates, issued by a
sibling CA rather than by whichever CA issued the certificate being asked
about. A verifier implementing only the delegation model rejects every one of
those answers as unauthorised — which is what this project did before M3, and
what made real Microsec OCSP responses come back `revocation_data_invalid`.

What keeps it honest is where the authority sits. A trusted responder is
vouched for by the caller's own store, through a full path validation with
`id-kp-OCSPSigning` required on the leaf; a responder that reaches no
configured anchor authorises nothing. So this can never admit a response whose
signer the operator had not already chosen to trust, and it is tried **last**,
so a CA's own word always wins where both apply. The path is validated at
`producedAt`, the instant the responder asserts it spoke: a certificate that
had expired by then was not entitled to say anything, and one that expired
afterwards said it while it still was.

`ocsp_responder_trusted` (`info`) is emitted when the third model was used, so
a reader can tell an answer that rests on the issuing CA from one that rests on
their own trust store. It reports rather than decides, so it never blocks.

#### Which answer wins

The reading order above is a preference about where to look first, not about
what to believe. The signature's own `RevocationValues` are supplied by the
signer, so a rule that stopped at the first definite answer let a genuine but
older embedded OCSP `good`, still inside its own `nextUpdate`, hide the
operator's newer CRL revoking the same certificate. For one certificate at one
validation time:

1. every source is consulted, and every usable, definite answer is gathered;
2. **a revocation from any source beats `good` from any other.** A source that
   records a revocation has seen something a source reporting `good` has not,
   and which tier it came from is irrelevant;
3. among answers that say the same thing, the one whose source speaks for the
   later instant is the one reported — the later `producedAt` where the source
   stated one, otherwise the later `thisUpdate` — because that source knew
   everything the earlier one did. A tie keeps the earlier source, which is the
   reading order;
4. the freshness rules and the revocation-after-validation-time rule below are
   unchanged, and are applied to the answer that was chosen.

`chain[].revocation.source` names the source the reported answer came from, so
"which CRL said this" is always answerable. When the usable sources did not
agree, `revocation_sources_disagree` (`info`) is emitted for the chain and the
same sentence is added to that certificate's `chain[].revocation.detail`. It
reports rather than decides, so it never blocks: the disagreement has already
been resolved by the rules above.

#### Tier fallback

**An unusable answer never ends the search.** The tiers above are consulted in
order, and a source that is found but refused — an OCSP response no model
authorises, a delta CRL, a CRL from a partition this certificate does not name
— is recorded and the next tier is tried. Only when every tier has been
exhausted is `revocation_data_invalid` or `revocation_status_unknown` reported.
A central responder this build cannot authorise is a very ordinary thing to
meet, and the CA's CRL two tiers down answers the same question.

The refusal stays visible either way. `chain[].revocation.detail` carries a
sentence saying what was refused and why — and, when a later source answered,
which one did: *"an OCSP response fetched online was refused because …; a CRL
fetched online was used instead"*. The path summary repeats it, so a reader who
only looks at the checks still learns that the responder was not usable. A
certificate that ends `unknown` gets the same sentence naming the cause, rather
than the generic "not signed by an authorised issuer, or it uses a form this
build refuses" that gave an operator nothing to act on.

SHA-1 is accepted in the `certID` and nowhere else. Those hashes identify which
certificate a response is about, they are not a signature, and RFC 6960 makes
SHA-1 the default, so refusing it would make every real response unusable while
defending nothing — the response's own signature still has to verify under the
pinned allowlist.

**Freshness.** Data whose `nextUpdate` is at or before the validation time is
stale, because a newer CRL or response may carry a revocation this one
predates. There is **no grace period**: a grace period is a decision to accept
expired data, which is exactly the decision a verifier must not make silently.
Data with no `nextUpdate` is usable only when its `thisUpdate` is at or after
the validation time.

**Time of revocation.** A revocation counts only when its `revocationTime` is
at or before the validation time. A certificate revoked *after* the instant
being validated was not revoked then, so it yields the distinct
`cert_revoked_after_validation_time` rather than `cert_revoked`.

Whether that blocks depends on how the validation time was arrived at, which is
the distinction ETSI EN 319 102-1 draws around the best-signature-time:

- **Proven** — the time came from a fully verified `xades:SignatureTimeStamp`.
  The signature demonstrably existed then, so a revocation dated afterwards
  says the certificate was withdrawn later and says nothing against the
  signature. Reported as `info`, with the revocation time and reason, and does
  not block.
- **Asserted** — the time came from `--at` or the clock. A caller can pass any
  `--at` they like, so an unproven time cannot be used to dismiss a real
  revocation. Reported as `unknown`, and blocks.

It is never `passed` either way: the certificate really was revoked, and the
message says when and why. A timestamp authority's own chain is always treated
as asserted, because the instant it is validated at is the `genTime` the token
itself claims, and that cannot also be the proof that dismisses a revocation
dated after it.

**Two chains, two answers.** A signature reports one revocation summary for its
signer's chain and one for each timestamp authority's, both under the same
code. Each message names which chain it is about.

**Per certificate**, each chain entry carries a `revocation` object with
`status` (`good`, `revoked`, `unknown`, `not_checked`, `trust_anchor`), the
check `code` that summarises it, the `source`
(`embedded_crl`, `embedded_ocsp`, `store_crl`, `store_ocsp`), and the times the
data stated. The path-level summary is one check: `revocation_ok` when every
non-anchor certificate has fresh, verified, non-revoked status; `cert_revoked`
when any was revoked at or before the validation time; and otherwise the worst
of `cert_revoked_after_validation_time`, `revocation_data_invalid`,
`revocation_data_stale`, and `revocation_status_unknown`.

**Naming what is missing.** The summary message names *which* certificate is
the problem — by role (`the end-entity certificate`, `the intermediate CA
<name>`) and by the issuer common name above it — and repeats the CRL
distribution point that certificate publishes when it has one. Only public CA
material is used: a CA's subject and any certificate's issuer are names of
organisations, which is exactly what a caller needs in order to fetch the right
file. The **subject** of the end-entity certificate is never repeated, because
that is the signer.

This matters because real Hungarian dossiers embed an OCSP response for the
**end-entity certificate only**. The intermediate and root CAs' status has to
come from CRLs the operator fetches into `--revocation-store`, and without
being told which certificate lacks data a caller cannot tell that apart from a
dossier that embeds nothing at all. See [trust.md](trust.md).

`--no-revocation` switches the check off. It emits `revocation_not_checked`
(`skipped`), which is blocking, so it is documented as producing **at most**
`indeterminate`.

### Online revocation fetching

`--online` is the only thing that makes openSzigno touch the network, and it
does so under a fixed policy the caller cannot widen.

**Who a URL may be fetched for.** Only a certificate on a certification path
the verifier **actually validated to a configured trust anchor** — from
`--trust-store` or from an ETSI trusted list — for a signature or a timestamp
it was evaluating. The set is not approximated: under `--online` the CLI runs
an entirely offline-style verification pass first, purely to learn it, and
`VerifyReport::validated_path_certificates_at` returns the certificates of
every chain whose own path check passed (`cert_path_ok`,
`timestamp_tsa_path_ok`), each paired with the validation time that chain was
evaluated at.
Everything else in the file — including a certificate parked in `ds:KeyInfo`
that chains perfectly well to the anchor but that no signature needed — is
outside the set and generates no traffic.

This is the load-bearing rule. A dossier carries its own certificates,
including the "issuer" that signed the signer, so "an embedded issuer signed
this" is a statement whoever wrote the dossier wrote on both sides of. Acting
on a URL out of such a certificate lets any file handed to the tool choose the
tool's next network destination. **With no anchors configured nothing is
fetched at all**, `policy.revocation` reads `online_no_anchors`, and both the
`revocation_policy` check and every `revocation_status_unknown` message say so
in as many words.

**Where the URLs come from.** Only from the certificates themselves: the
`cRLDistributionPoints` extension's `fullName` URIs and the
`authorityInfoAccess` extension's `id-ad-ocsp` access locations. These are
fields a CA wrote into a certificate that a trust anchor signed. No URL is ever
taken from the dossier's XML, from a redirect to another host, or from the
environment, and a `ds:Reference` or an `xades:Include` is still never
dereferenced.

**What is fetched, and when.** Nothing, for a certificate the caller's own
material already answers for. Before any request is made, each certificate is
put to the *same* offline code path the verdict will use, **at the validation
time its path was evaluated at**; only a certificate that comes back without a
definite answer is fetched for. That time is not one global instant: a signer
path a verified timestamp restores is evaluated at the token's `genTime`, a
timestamp authority's own path at the `genTime` it asserts, and everything
else at `--at` or the clock. Asking at one global time both fetches for
certificates the run already covers and calls a certificate covered by data
that does not apply at the instant the verdict rests on.

**In bounded rounds.** One pass is not enough, because evidence fetched for
one path can create another. A signer whose certificate has expired has no
validated path at the clock, so nothing may be fetched for it; fetching the
revocation evidence its signature timestamp's authority needed can verify that
timestamp, move the signer's validation time back to the proven instant and
restore its path. A single fetch pass makes that discovery after fetching has
finished, and the signer's own revocation data is never fetched. So the CLI
runs at most `MAX_ONLINE_ROUNDS` (3) rounds: each round verifies with the
store widened by everything fetched so far, computes the validated-path
certificate set with its times, and fetches only for what became eligible in
that round. The run stops as soon as a round turns up nothing new, which is
the ordinary case after the first, and stops in any case at the bound with
whatever it has. The certificate budget below belongs to the run, so rounds
cannot multiply the traffic one dossier can generate. OCSP is tried before
CRLs, because a response answers about one certificate where a CRL is a list
that may run to megabytes. Certificates whose issuer is not to hand are skipped
— a CRL could not be checked against them anyway — and so are self-signed
roots, whose revocation is never asked about.

**One request per question.** CRLs are deduplicated by URL: a CRL is a list and
one copy answers for everyone on it. OCSP is deduplicated by **responder URL
and `certID` together**, because a response answers about one certificate — two
certificates issued by the same CA name one responder and are two different
questions, and deduplicating by URL alone asked the first and silently dropped
the second, leaving it uncovered for a reason nothing in the report named.

**The destination policy.** The URL is treated as attacker-chosen until the
trust gate above has been passed, and even then it must name a destination this
build is willing to open a socket to:

| Rule | Default | Why |
| --- | --- | --- |
| Scheme | `http` and `https` only | Every other scheme is refused, never rewritten into one this build speaks. |
| Userinfo | refused, always | `user:password@host` is a way of writing a URL that reads as one host and names another, and it is credential material this tool has no business sending. `--online-allow-private` does not waive it. |
| Address | loopback (`127/8`, `::1`), RFC 1918 private (`10/8`, `172.16/12`, `192.168/16`), link-local (`169.254/16`, `fe80::/10`), unique-local (`fc00::/7`), unspecified (`0.0.0.0/8`, `::`), broadcast (`255.255.255.255`) and multicast (`224/4`, `ff00::/8`) are all refused, as are carrier-grade NAT (`100.64.0.0/10`), IETF protocol assignments (`192.0.0.0/24`), benchmarking (`198.18.0.0/15`), the deprecated site-local prefix (`fec0::/10`), the tunnel prefixes 6to4 (`2002::/16`), Teredo (`2001::/32`) and NAT64 (`64:ff9b::/96`), the cloud metadata addresses `169.254.169.254` and `fd00:ec2::254`, and the name `localhost` (and `*.localhost`) | Otherwise a dossier could point the verifier at `http://169.254.169.254/` — instance metadata, credentials included — or at a service on the operator's own subnet, turning a signature check into an SSRF primitive. An IPv4-mapped (`::ffff:a.b.c.d`) or IPv4-compatible (`::a.b.c.d`) IPv6 address is judged as the IPv4 address it carries, so neither is a way round any of these; the three tunnel prefixes are refused outright for the same reason, since each carries an IPv4 destination the IPv4 rules would never see. The two metadata addresses are named in their own refusal, because that is the one an operator wants to be told about explicitly. |
| Resolved address | re-checked against the same ranges before connecting | A public name that resolves to `127.0.0.1` is refused on the address, not on the name, so DNS rebinding does not walk past the rule. |
| The address that is dialled | exactly the addresses the check approved | The policy hands its resolution to `ureq` as a pinned answer for that host and port, and a name that was not vetted for the fetch in hand does not resolve at all: there is no second lookup, so a zone that answers with a public address and then with a private one has no window between the check and the socket. A host that resolves to nothing is a `transport` failure and nothing is contacted. |
| The name that is verified | unchanged | Pinning is an address decision only. The URL is sent as published, so the `Host` header, the TLS SNI value and the certificate host-name verification all still use the name the certificate named. |
| Every hop | the URL the certificate published and **each redirect target** go through the whole policy, and each is pinned in its own right | A redirect already may not leave the host, but "the same name" and "the same address" are different statements. |
| `redirect_downgrade` | a redirect from `https` to `http` is refused, for every request kind | A redirect is the peer's choice. Same host, same certificate, and yet the next request would go out in the clear carrying whatever the first one carried: for `sign --csc`, the bearer token in the header and the PIN and one-time password in the body. The refusal is decided before the loop comes round, so the downgraded target is never contacted. |
| `credentials_require_https` | a request carrying credentials requires `https` on **every** hop, the first included | Credentials are a bearer token in the `Authorization` header, or a body the caller marked sensitive, which every `sign --csc` request is. The one exemption is a loopback service under `--online-allow-private`, granted on the addresses the policy approved rather than on the host text, which is what this project's own test servers are. Without the flag the refusal comes before the host is even resolved. |
| The `Authorization` header | attached only after the target has passed every check above | A target that failed the destination policy, the credential rule or the address pin is never sent the header: it is put on the request in one place, reached only from the vetted branch of the fetch loop. |

`--online-allow-private` waives the address rules — and only those — for an
internal CA that really does publish on a private network. It does not waive
resolution: an address is still needed to connect to, and loopback with the
flag is vetted down to the address like any other destination. This project's
own test suite passes it, because it serves a synthetic PKI from `127.0.0.1`.

With `--online-proxy` the request goes to the proxy and the proxy resolves the
destination, so pinning cannot apply to the destination: `ureq` only asks about
the proxy's own host, which is resolved normally. The destination policy still
runs on the URL and still refuses a scheme, userinfo, or an address it does not
permit; what it cannot promise is that the socket the *proxy* opens goes where
the policy looked.

**The transport policy.**

| Rule | Value | Why |
| --- | --- | --- |
| Schemes | `http` and `https`, exactly as published | Neither is rewritten. Upgrading `http` to `https` is a guess about a host's configuration. Confidentiality is not the point: these are public documents and every one is signature-checked before it is believed. |
| Connect timeout | 5 s | |
| Total timeout | 20 s per fetch | A fetch that exceeds it is a named failure, never a hang. |
| Size cap | `MAX_REVOCATION_ITEM_BYTES` (16 MiB) for a CRL, 64 KiB for an OCSP response | Enforced by the reader, so a server that lies about `Content-Length` cannot make the run allocate more. The CRL cap is the *verifier's own* limit, re-exported: a download cap larger than what the tier walk will parse meant a CRL could arrive, be stored, and then answer nothing. |
| Redirects | at most 3, **never to another host**, and **never from `https` to `http`** | The authority for a URL is the certificate, and the certificate named one host. The port is part of the host. A downgrade is refused as `destination_refused` with the rule `redirect_downgrade`. |
| Proxy | none, unless `--online-proxy URL` | `HTTP_PROXY` and its relatives are ignored. A verifier that silently routed its revocation traffic through whatever the shell happened to set would hand an attacker who controls that variable a way to feed it chosen bytes. With a proxy the proxy does the connecting, so the destination policy still checks the URL but no longer decides which socket is opened. |
| Requests | `GET` for a CRL; `POST` of an RFC 6960 `OCSPRequest` as `application/ocsp-request` for OCSP | The `certID` uses **SHA-256**, which is inside the pinned allowlist. No nonce is sent: a nonce defends a live request against replay, and the verifier deliberately ignores nonces because it must also read archived responses. |
| Volume | at most 32 certificates per run, rounds included, at most 4 URLs per certificate | Opening one dossier cannot generate unbounded traffic. |

**What fetching can and cannot do.** It can only *add* data. Every fetched
artefact is classified and then judged by exactly the offline rules — issuer
match, signature by an authorised issuer, scope, freshness — so a server that
answers with a well-formed CRL from the wrong CA changes nothing, and one that
answers with an HTML error page is `invalid`. Online material is consulted
**last**, after the signature's own `RevocationValues` and the revocation
store, so it can never displace an answer that was already to hand.

**When it fails.** Each failure contributes one `online_fetch_failed` (`info`)
naming the URL and a failure class: `timeout`, `http status <code>`,
`too large` (with the limit it exceeded), `redirect`, `invalid`, `transport`,
`destination_refused` (with the rule that refused it — nothing was contacted at
all, and `redirect_downgrade` and `credentials_require_https` are two of those
rules), or `cache_collision` (the artefact was fetched, but `--online-cache`
already holds a different file under that name and nothing was overwritten).
The class is reported
because the remedies differ — a timeout is somebody else's outage, a `404` is a
stale URL in an old certificate, and "not a CRL" is what a captive portal looks
like from here. A URL is public CA material, so naming it is safe and is the
one thing that makes the failure actionable. Nothing panics and nothing hangs.

It is **informational, and that does not weaken anything.** A failed fetch is a
fact about the network, not about a certificate. Whether a certificate ended up
covered is decided by the verifier, from the data it actually holds, and a
fetch that did not happen leaves it exactly as uncovered as it was — which the
chain's own `revocation_status_unknown` reports, and which blocks. The blocking
is therefore already done, once, by the check that knows *which* chain is short
of data. Making the per-URL check block as well would add nothing there and
would do harm: a fetch attempted for a certificate no verdict depended on — an
over-fetch, or the TSA of a container `es:TimeStamp`, whose chain is
deliberately not allowed to decide anything — would drag a dossier whose every
signature is `valid` down to `indeterminate`.

**Reproducibility.** `--online-cache DIR` writes every fetched artefact into
`DIR/crls/` and `DIR/ocsp/`, which is the `--revocation-store` layout. A CRL is
named by the SHA-256 of its own bytes; an **OCSP response is named by the
SHA-256 of the `certID` it answers about followed by the SHA-256 of its own
bytes**, so two answers from one responder are two files whose names say which
is which — the same distinction the request deduplication makes.

The cache is written with the same descriptor-relative machinery as an
extraction (`extract/output_dir.rs`): the directory is opened once with
`O_DIRECTORY | O_NOFOLLOW` and walked one component at a time, and each file is
created with `O_CREAT | O_EXCL | O_NOFOLLOW`. **Nothing is ever truncated or
replaced.** A name that already holds exactly these bytes is the idempotent
case — which is also what a concurrent writer looks like — and is left alone; a
name that holds anything else, or a symlink, is reported as one
`online_fetch_failed` with the class `cache_collision` and the run continues,
because a cache is an optimisation and a strange file in it is not a reason to
fail a verification that has already been done. A later run
with `--revocation-store DIR` and no `--online` therefore reaches the same
answer with no network at all — the
only difference being that the source is reported as `store_crl` rather than
`online_crl`. Nothing is ever deleted from the cache.

`chain[].revocation.source` reports `online_crl` and `online_ocsp` for answers
that came from the network. `policy.revocation` reads `online` for a run that
was given the flag and had at least one trust anchor to gate fetching on,
whether or not anything was actually fetched, and `online_no_anchors` for a run
that was given the flag with no anchor configured, where nothing was fetched
and nothing could have been. `--online` and `--no-revocation` cannot be
combined.

### Verify result shape

`schema_version` stays at `1`: `verify` adds a new `command` value and its own
`data`, and changes no existing field's contract. `signatures_verified` in
`inspect` and `list` output stays `false`, because those commands still do not
verify anything.

```json
{
  "schema_version": 1,
  "ok": true,
  "command": "verify",
  "input": { "format": "microsec-es3", "bytes": 8337 },
  "data": {
    "verdict": "indeterminate",
    "verification_time": {
      "requested": "2020-06-01T00:00:00Z",
      "effective": "2020-06-01T00:00:00Z",
      "source": "requested"
    },
    "policy": {
      "revocation": "offline",
      "trust_store": "configured",
      "trust_lists": [
        {
          "territory": "HU",
          "sequence_number": 99,
          "issue_date": "2026-07-15T08:42:53Z",
          "next_update": "2027-01-15T00:00:00Z",
          "anchors": 41,
          "signature_verified": true
        }
      ],
      "trust_snapshot": null,
      "legacy_algorithms_allowed": false,
      "digest_algorithms": ["sha256", "sha384", "sha512"],
      "signature_algorithms": ["rsa-pkcs1-sha256", "…"],
      "c14n_algorithms": ["http://www.w3.org/TR/2001/REC-xml-c14n-20010315", "…"],
      "transforms": ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "…"]
    },
    "limits": { "max_signatures": 64, "…": 0 },
    "counts": {
      "signatures": 1,
      "signatures_valid": 0,
      "signatures_invalid": 0,
      "signatures_indeterminate": 1,
      "timestamps": 0,
      "timestamps_verified": 0,
      "documents_covered": 1,
      "documents_uncovered": 1,
      "documents_undetermined": 0
    },
    "checks": [
      { "code": "signature_count_within_limits", "status": "passed",
        "message": "the number of signatures is within the verification limits" }
    ],
    "documents": [
      {
        "index": 0,
        "object_ref": "obj0",
        "nested_dossier": false,
        "coverage": "covered",
        "covered_by": [
          { "signature_index": 0, "via": "direct", "verdict": "valid" }
        ]
      },
      {
        "index": 1,
        "object_ref": "obj1",
        "nested_dossier": false,
        "coverage": "uncovered",
        "covered_by": [],
        "reason": "no signature's resolved references include this document"
      }
    ],
    "signatures": [
      {
        "index": 0,
        "scope": "document",
        "placement": "document",
        "role": "signature",
        "parent_signature_index": null,
        "countersigns": [],
        "document_index": 0,
        "signature_id": "sig-doc",
        "verdict": "indeterminate",
        "xades_level": "detected",
        "signing_time": "2020-01-01T00:00:00Z",
        "signing_certificate_index": 0,
        "signing_certificate": {
          "subject_cn": "…",
          "issuer_cn": "…",
          "serial_hex": "01a2b3",
          "not_before": "2019-01-01T00:00:00Z",
          "not_after": "2039-01-01T00:00:00Z",
          "key_algorithm": "rsa",
          "key_bits": 2048,
          "sha256_fingerprint": "…",
          "qualified": true
        },
        "qualified": true,
        "qualified_signature_device": false,
        "qualified_service": "Qualified e-Szigno CA 2009",
        "chain": [
          {
            "subject_cn": "…",
            "issuer_cn": "…",
            "serial_hex": "01a2b3",
            "not_before": "2019-01-01T00:00:00Z",
            "not_after": "2039-01-01T00:00:00Z",
            "is_trust_anchor": false,
            "source": "key_info",
            "trust_anchor_origin": null,
            "revocation": {
              "status": "good",
              "code": "revocation_ok",
              "source": "embedded_ocsp",
              "revocation_time": null,
              "reason": null,
              "this_update": "2020-05-15T00:00:00Z",
              "next_update": "2020-07-01T00:00:00Z",
              "produced_at": "2020-05-15T00:00:00Z",
              "responder_model": "delegated",
              "detail": null
            }
          },
          { "subject_cn": "…", "issuer_cn": "…", "serial_hex": "…",
            "not_before": "…", "not_after": "…",
            "is_trust_anchor": true, "source": "trust_store",
            "trust_anchor_origin": "trust_list",
            "revocation": { "status": "trust_anchor",
              "code": "revocation_not_checked", "source": null,
              "revocation_time": null, "reason": null,
              "this_update": null, "next_update": null, "produced_at": null,
              "responder_model": null, "detail": null } }
        ],
        "references": [
          {
            "index": 0,
            "uri": "#obj0",
            "resolved_to": "Dossier/Documents/Document/Object",
            "digest_algorithm": "sha256",
            "transforms": ["http://www.w3.org/2001/10/xml-exc-c14n#"],
            "status": "passed"
          }
        ],
        "xades": {
          "present": true,
          "signing_time": "2020-01-01T00:00:00Z",
          "signing_certificate": {
            "form": "v2",
            "digest_algorithm": "sha256",
            "issuer_serial_present": true,
            "matched": true
          },
          "signature_policy": "implied",
          "signature_policy_id": null,
          "signature_timestamps": 1,
          "archive_timestamps": 0,
          "unvalidated_properties": []
        },
        "timestamps": [
          {
            "kind": "signature-timestamp",
            "gen_time": "2020-06-01T09:00:00Z",
            "accuracy_seconds": 1,
            "serial_hex": "2a",
            "imprint_algorithm": "sha256",
            "tsa_certificate": {
              "subject_cn": "…", "issuer_cn": "…", "serial_hex": "…",
              "not_before": "…", "not_after": "…",
              "key_algorithm": "rsa", "key_bits": 2048,
              "sha256_fingerprint": "…", "qualified": null
            },
            "chain": [
              { "subject_cn": "…", "issuer_cn": "…", "serial_hex": "…",
                "not_before": "…", "not_after": "…",
                "is_trust_anchor": false, "source": "timestamp_token",
                "trust_anchor_origin": null,
                "revocation": { "status": "good", "code": "revocation_ok",
                  "source": "store_crl", "revocation_time": null,
                  "reason": null, "this_update": "2020-05-01T00:00:00Z",
                  "next_update": "2020-07-01T00:00:00Z", "produced_at": null,
                  "responder_model": null, "detail": null } }
            ],
            "verified": true,
            "checks": [
              { "code": "timestamp_imprint_ok", "status": "passed",
                "message": "the message imprint matches the data the timestamp covers" }
            ]
          }
        ],
        "validation_time": "2020-06-01T09:00:00Z",
        "validation_time_source": "timestamp",
        "checks": [
          { "code": "reference_digest_ok", "status": "passed",
            "message": "4 of 4 reference digests matched" }
        ]
      }
    ]
  },
  "warnings": [],
  "errors": []
}
```

Notes on the shape:

- `data.documents[]` is the per-document coverage inventory: one entry per
  `es:Document` in `es:Documents`, in source order, with `index` and
  `object_ref` from the structural model (`null` on a document the parser did
  not model), `nested_dossier`, the `coverage` state, the signatures in
  `covered_by`, and a `reason` when there is something to say. **No title ever
  appears here.** `data.counts` gains `documents_covered`,
  `documents_uncovered` and `documents_undetermined`, which count the states
  of the same name only: a `covered_unverified` or `not_modelled` document is
  in `data.documents` and in none of the three. See
  [Document coverage](#document-coverage).
- `placement` is `document`, `dossier`, `countersignature`, or `unknown`, and
  `scope` is an alias of it kept from the phase-3 report: both always carry the
  same value. `role` is `signature` or `countersignature`.
  `parent_signature_index` names the signature a nested
  `xades:CounterSignature` is embedded in and is `null` for every other
  placement, including an e-dossier-form countersignature, which is a sibling
  and not a nesting. `countersigns` lists the indexes of every signature whose
  `ds:SignatureValue` this one's references resolve to. See
  [Countersignatures](#countersignatures).
- `checks` at the top level belongs to the dossier; each signature carries its
  own `checks`, ordered by pipeline stage, so a consumer reading top to bottom
  sees the same order the tool evaluated.
- `code` and `status` are stable; `message` is human text and is not.
- **A consumer must treat an unknown `code` as blocking unless its `status` is
  `passed` or `info`.** Later versions add codes, and a consumer that ignores
  what it does not recognise would silently weaken its own policy.
- `status: "info"` is the one non-blocking status. It exists so that a check
  which only *reports* something — a loosely filled `extendedKeyUsage`, the
  presence of a claimed signing time, a qualified determination — can be
  emitted without pretending the tool failed to determine anything. Every other
  non-`passed` status keeps the verdict below `valid`, which is what makes
  "`unknown` always blocks" true without exception.
- Absent data is `null`, never an optimistic default. `qualified: null` means
  "not determined", which is different from `false`.
- `chain[].trust_anchor_origin` is `trust_store` or `trust_list` on the anchor
  entry and `null` on every other entry, so a consumer can tell an anchor a
  human dropped into a directory from one an EU trusted list vouches for.
- `chain[].revocation` carries this certificate's own revocation answer with
  the source it came from. `status` is one of `good`, `revoked`,
  `revoked_after_validation_time`, `unknown`, `not_checked`, or
  `trust_anchor`, and `source` is one of `embedded_crl`, `embedded_ocsp`,
  `store_crl`, `store_ocsp`, `online_crl`, or `online_ocsp`.
  `responder_model` is `issuer`, `delegated` or `trusted` for an answer that
  came from OCSP and `null` otherwise; `detail` carries the sentence about a
  source that was consulted and refused, whether or not a later one answered.
  The anchor's entry is always `trust_anchor`, because the
  anchor is never asked about; the whole object is `null` only when no path was
  built at all.
- `qualified`, `qualified_signature_device` and `qualified_service` sit on the
  signature, and `qualified` is mirrored onto
  `signing_certificate.qualified`. `qualified_service` names the trusted-list
  service that decided it, so a caller can check the determination against the
  list themselves; it is `null` when none matched.
- `references[].resolved_to` is filled in by the resolution stage, so it is
  present even when the run stopped at a policy failure and no digest was ever
  recomputed. In that case every `references[].status` is `skipped` and
  `resolved_to` still shows what each URI pointed at.
- `signing_time` is the `xades:SigningTime` the signature **claims**,
  normalised to RFC 3339 UTC (`null` when absent or unparseable). It is read,
  never trusted, and it never becomes a validation time: only `--at`, a
  verified timestamp, and the clock do that. The `signing_time_present` check
  reports that it was read, always with status `info`: its presence decides
  nothing either way.
- `xades` reports what the qualifying properties said, not what was concluded
  from them: the check codes carry the conclusions.
  `xades.signing_certificate` is `null` when the signature carries no
  `SigningCertificate` property at all, and `matched: false` when it carries
  one that no offered certificate answers to.
- `timestamps[]` holds one entry per `xades:SignatureTimeStamp`, each with its
  own `checks`. `verified` is true only when every one of those checks passed,
  which is the condition for `gen_time` to become the validation time. A token
  that failed to parse reports `gen_time: null` and a single failed
  `timestamp_token_parsed`. The signature's own `checks` carry one
  `timestamp_verified` per token, so a consumer reading only the signature
  level still sees the outcome.
- `validation_time` and `validation_time_source` are per signature; see
  [Validation time](#validation-time). `data.verification_time` remains the
  run-level `--at` and clock reading.
- `xades_level` is still a placeholder: `"detected"` or `null`. Level
  detection (B-B, B-T, B-LT, B-LTA) is not implemented, and reporting a level
  would imply a determination this build does not make.
- The certificate summary is limited on purpose to subject and issuer common
  names, serial, validity, key algorithm and size, and the SHA-256
  fingerprint. Full distinguished names and subject alternative names stay out
  of the report. **`verify --json` output can contain personal data of
  signers**, which is why those fields are structured rather than interpolated
  into free text: no check message ever quotes a certificate subject, a
  document title, or payload content.

### Verify check codes

`status` is one of `passed`, `failed`, `skipped`, `unknown`, or `info`.

- `unknown` means the tool could not determine the answer, and is never a
  substitute for `failed`.
- **`skipped` means a check the policy requires was not performed**, and only
  that. It is not a place to file observations. A property this build reads but
  does not act on, or evidence it declines to re-verify, is `info`: it did not
  fail to answer a required question, so it must not block. Emitting `skipped`
  for such a thing caps a signature at `indeterminate` for carrying *more*
  evidence than the minimum, which is precisely backwards.
- `info` is the only non-blocking status; everything else that is not `passed`
  keeps the verdict below `valid`.

The three checks that are still `skipped`, and why each is a required check
that was not performed: `xades_absent` (no signed statement of which
certificate signed, so the `SigningCertificate` binding could not be checked),
`timestamp_not_checked` (a timestamp is present in a form this build cannot
verify), and `revocation_not_checked` (the caller switched revocation off).

| Code | Status when emitted | Meaning |
| --- | --- | --- |
| `no_signatures` | `unknown` | The dossier carries no `ds:Signature`, so there is nothing that could be valid. |
| `signature_count_within_limits` | `passed` | The signature count is within `max_signatures`. |
| `signature_limit_exceeded` | `failed` | More signatures than `max_signatures`; the excess is not examined. |
| `signatures_unsupported` | `unknown` | One or more signatures sit at a placement this build does not support; the message names the count and the indexes. Blocking, so such a dossier cannot be `valid`. `unknown`, never `failed`: incomplete support is missing information, not evidence of forgery, and those signatures' own verdicts are left out of the dossier verdict. |
| `documents_all_covered` | `passed` / `info` | Every modelled document is covered. `passed` when each is covered by a signature that verified; `info` when at least one is covered only by signatures that did not verify, because that finding is already on those signatures. See [Document coverage](#document-coverage). |
| `documents_uncovered` | `unknown` | One or more modelled documents are covered by no signature; the message names the count and the indexes. Blocking, so a dossier with an unsigned document cannot be `valid`. `unknown`, not `failed`: an unsigned sibling is missing information, not evidence against a signature that did verify. |
| `documents_coverage_undetermined` | `unknown` | The coverage of one or more modelled documents could not be determined, because a signature that might cover them could not be evaluated. The message names the count. Blocking, for the same reason. |
| `sig_structure` | `passed` | `ds:SignedInfo`, `ds:SignatureValue`, the methods, and at least one reference are present, within limits, and in the cardinality and order the XMLDSig schema fixes. |
| `sig_structure_invalid` | `failed` | One of those is missing, duplicated, out of order, malformed, or over a limit, or one of the three sequenced elements carries an unexpected child. The message names the element and which of those it is. See [XMLDSig structural rules](#xmldsig-structural-rules). |
| `sig_placement` | `passed` | The signature is at a placement this build describes: `//es:Document/ds:Signature`, `//es:Dossier/ds:Signature`, or the `ds:Signature` inside an `xades:CounterSignature`. |
| `sig_placement_invalid` | `failed` | It is not, and the message names the reason. On its own this does **not** make the dossier `invalid`; see `signatures_unsupported` and [Countersignatures](#countersignatures). |
| `countersignature_binding_ok` | `passed` | The countersignature's references resolve to the `ds:SignatureValue` it must attest. |
| `countersignature_binding_missing` | `failed` | They do not, so nothing is countersigned. |
| `countersignature_binding_mismatch` | `failed` | A nested signature resolves to a `ds:SignatureValue` other than its lexical parent's. The countersignature-wrapping check. |
| `nested_signatures_unsupported` | `info` | A signature is nested inside this one in a shape this build does not support. Informational: the enclosing signature does not cover its own unsigned properties, so nothing dropped in there can change what it says. |
| `c14n_method_allowed` | `passed` | `ds:CanonicalizationMethod` is implemented. |
| `c14n_unsupported` | `failed` | A canonicalization algorithm, on `ds:SignedInfo` or in a transform, is known but not implemented. |
| `signature_algorithm_allowed` | `passed` | `ds:SignatureMethod` is inside the allowlist. |
| `digest_algorithm_allowed` | `passed` | Every `ds:DigestMethod` is inside the allowlist. |
| `algorithm_rejected` | `failed` | A signature method, a digest method, or a signing key is outside the pinned policy. May appear more than once. |
| `algorithm_legacy_allowed` | `unknown` | SHA-1 was admitted because `--allow-legacy-algorithms` was given. Blocking: caps the verdict at `indeterminate`. May appear twice, once for the signature method and once for the digests. |
| `transforms_allowed` | `passed` | Every transform is inside the allowlist. |
| `transform_not_allowed` | `failed` | A transform is outside it; XSLT and XPath always are. |
| `references_same_document` | `passed` | Every `ds:Reference/@URI` is `""` or `#id`. |
| `reference_external` | `failed` | A reference names something else. Nothing is ever dereferenced. |
| `references_resolve` | `passed` | Every `#id` resolves to exactly one node in the validated ID space. |
| `reference_unresolved` | `failed` | One does not. |
| `reference_scope_complete` | `passed` | Every element the container mandates is covered. |
| `reference_scope_incomplete` | `failed` | One is not; the message names which, and says so when a reference declared the `SignedProperties` `Type` without resolving to one. |
| `reference_scope_unknown` | `unknown` | The mandated set is undefined for this signature's placement. |
| `reference_digest_ok` | `passed` | Every reference digest recomputed correctly. |
| `reference_digest_mismatch` | `failed` | One did not, or its transform chain could not be applied. |
| `signedinfo_canonicalization` | `passed` | `ds:SignedInfo` canonicalized without error. |
| `signedinfo_canonicalization_failed` | `failed` | It did not. |
| `signature_value_ok` | `passed` | `ds:SignatureValue` verified over the canonical `ds:SignedInfo`. |
| `signature_value_invalid` | `failed` | It did not verify, or is not canonical Base64. |
| `xades_present` | `passed` | `xades:QualifyingProperties` was found for this signature. |
| `xades_absent` | `skipped` | None was found; this is a bare XMLDSig signature, so nothing signed says which certificate signed it and the `SigningCertificate` binding could not be checked. Blocking. |
| `xades_not_validated` | `info` | Unsigned qualifying properties this build does not validate are present; the message and `xades.unvalidated_properties` name them. Informational: they live outside the signature and cannot change what it says, and the ones that carry evidence this build *does* use — `CertificateValues`, `RevocationValues`, `TimeStampValidationData` — are consumed and not counted here. Omitted entirely when nothing is left to name. |
| `xades_signing_certificate_bound` | `passed` | The signing certificate matches the digest the signed `SigningCertificate` / `SigningCertificateV2` property names. |
| `xades_signing_certificate_mismatch` | `failed` | It does not: no offered certificate answers to the digest, an issuer and serial contradict it, the declared digest algorithm is outside the allowlist, or the certificate whose key verified the signature is not the digested one. The certificate-substitution check. |
| `xades_signing_certificate_absent` | `unknown` | The signature carries no such property in the signed properties its own references cover, so nothing signed says which certificate signed it. |
| `xades_extra_qualifying_properties` | `info` | More than one `xades:QualifyingProperties` belongs to this signature; the one its own references cover is read and the others are ignored. Informational: an unreferenced `ds:Object` is open content the schema allows, so an extra one says nothing about the signature and must not be able to block it. |
| `xades_signature_policy_implied` | `info` | An implied signature policy is declared. Informational: a declared policy describes how the signature was made and says nothing about whether it is sound, so it does not block. No policy is processed. |
| `xades_signature_policy_explicit` | `info` | An explicit signature policy is declared. Its identifier is reported; no policy document is fetched or applied. Informational for the same reason. |
| `signing_certificate_available` | `passed` | A usable certificate was found in `ds:KeyInfo`. |
| `signing_certificate_missing` | `failed` | None was. |
| `signing_time_present` | `info` | Reports whether a claimed `xades:SigningTime` was read. Informational: the claim is unauthenticated whether it is there or not, so its presence decides nothing. |
| `cert_malformed` | `failed` | A certificate in the path could not be re-encoded or its signature is not a whole number of bytes. |
| `cert_path_ok` | `passed` | A path to a configured anchor was built and every rule above holds. |
| `cert_path_unknown` | `unknown` | No trust anchors were configured. |
| `cert_path_untrusted` | `failed` | No path to a configured anchor exists. The message says how many candidates were considered and names the issuer CN of the highest certificate reached, which is the public CA name a caller needs to add to the store. |
| `cert_path_search_exhausted` | `unknown` | Path building hit its expansion budget. The tool stopped looking, which is not a statement that no path exists, so it does not make a signature `invalid`. |
| `cert_path_length_exceeded` | `failed` | A CA is followed by more intermediates than its `pathLenConstraint` allows. |
| `cert_expired` | `failed` | A certificate in the path had expired at the validation time. |
| `cert_not_yet_valid` | `failed` | One was not yet valid then. |
| `cert_signature_invalid` | `failed` | A link is not correctly signed by its issuer. |
| `cert_algorithm_rejected` | `failed` | A certificate signature algorithm or key is outside the policy. |
| `cert_key_usage_invalid` | `failed` | A CA does not permit `keyCertSign`; the leaf permits neither `digitalSignature` nor `nonRepudiation`; or the leaf's `extendedKeyUsage` names only unrelated purposes and it does not assert `nonRepudiation`. |
| `cert_key_usage_advisory` | `info` | The signing certificate asserts `nonRepudiation` but its `extendedKeyUsage` names only unrelated purposes. The message names the OIDs found. Informational: ETSI EN 319 412-2 makes `nonRepudiation` the signal, and a loosely filled EKU alongside it is a reporting matter. |
| `cert_basic_constraints_invalid` | `failed` | An issuing certificate is not marked as a CA. |
| `cert_name_constraint_violation` | `failed` | A certificate violates a name constraint imposed by a CA above it. |
| `cert_unsupported_critical_extension` | `failed` | A certificate carries a critical extension this validator does not understand. |
| `revocation_policy` | `info` | Reports the revocation policy actually applied: `offline`, `online` with `--online`, `online_no_anchors` when `--online` was given with no trust anchor configured — so nothing was fetched, because revocation data is only fetched for a certificate on a path to an anchor — or off with `--no-revocation`. Always emitted, so the policy is visible even when no data was found. |
| `revocation_not_checked` | `skipped` | Emitted **only** when the caller passed `--no-revocation`. Blocking, so switching the check off is documented as producing at most `indeterminate`. |
| `revocation_ok` | `passed` | Every certificate in the path except the trust anchor has fresh, verified, non-revoked status. Emitted once per chain — the signer's and each timestamp authority's — and the message names which. |
| `cert_revoked` | `failed` | A certificate in the path was revoked at or before the validation time. `certificateHold` counts. |
| `cert_revoked_after_validation_time` | `info` / `unknown` | A certificate was revoked *after* the instant being validated, so that revocation did not apply then. `info` when the validation time was **proven** by a fully verified signature timestamp, `unknown` when it was merely asserted by `--at` or the clock. Never `passed`: the certificate really was revoked, and the message gives the time and reason. |
| `revocation_status_unknown` | `unknown` | No usable revocation data covers a certificate in the path, or no path was built to ask about. Blocking. A failed `--online` fetch reaches a verdict through this check and not on its own; see `online_fetch_failed`. |
| `revocation_data_stale` | `unknown` | The data's `nextUpdate` had passed at the validation time, or it carries none and its `thisUpdate` precedes it. Also the OCSP `unknown` status. |
| `revocation_data_invalid` | `unknown` | Every source that covered a certificate was found but could not be used: signed by someone unauthorised, a delta or indirect CRL, an unimplemented `issuingDistributionPoint` form, a critical CRL extension this build does not implement, an OCSP response whose status is not `successful`, or an item larger than `MAX_REVOCATION_ITEM_BYTES`, whose size and limit the message names. The message names the cause. Emitted only after every tier has been tried. `unknown`, not `failed`: unusable data means the tool could not answer. |
| `online_fetch_failed` | `info` | Under `--online`, one fetch did not produce a usable artefact. The message names the URL and the failure class: `timeout`, `http status <code>`, `too large` with the limit, `redirect`, `invalid`, `transport`, `destination_refused` with the rule that refused the destination before any socket was opened (`redirect_downgrade` for a redirect that would leave `https` for `http`, `credentials_require_https` for a request carrying credentials over a scheme that is not `https`, and the address and scheme rules), or `cache_collision` when `--online-cache` already held a different file under an artefact's name and nothing was overwritten. Informational: whether the missing data mattered is answered by the chain that needed it, through `revocation_status_unknown`, which blocks. |
| `revocation_sources_disagree` | `info` | The usable revocation sources for one certificate did not say the same thing: one recorded a revocation and another reported it as not revoked. The message names both sides and which chain it is about. Reports rather than decides — the disagreement is already settled by [Which answer wins](#which-answer-wins), where a revocation beats a `good` from any other source — so it never blocks. |
| `ocsp_responder_trusted` | `info` | An OCSP response was accepted under the RFC 6960 section 2.2 trusted-responder model: the responder is not the issuing CA and that CA did not delegate to it, but its certificate carries `id-kp-OCSPSigning` and chains to a configured anchor. Reported because this rests on the caller's trust store rather than on the issuing CA's word. |
| `trust_list_loaded` | `info` | A `--trust-list` file was read; the message says how many anchors it contributed. |
| `trust_list_unverified` | `unknown` | A trusted list was used without `--trust-list-signer`, so its own signature was not checked. Blocking. |
| `trust_list_signature_ok` | `passed` | The list's enveloped XMLDSig signature verified against the supplied signer certificate and covers the whole document. |
| `trust_list_signature_invalid` | `failed` | It did not verify, does not cover the whole list, uses an algorithm or transform outside the allowlist, or is absent while a signer was demanded. |
| `trust_list_service_not_granted` | `unknown` | A path was built and validated but ends at a trusted-list anchor the list does not record as granted at the validation time for the use the path was built for. Replaces `cert_path_ok` (and, for a timestamp, `timestamp_tsa_path_ok`); the other candidate paths are tried first. `unknown`, never `failed`: missing trust is not evidence against the signature, so it caps the verdict at `indeterminate` rather than making it `invalid`. See [A path may only end at a service that was granted then](#a-path-may-only-end-at-a-service-that-was-granted-then). |
| `certificate_qualified` | `info` | The chain ends at a trusted-list CA/QC service granted at the validation time, and any post-eIDAS certificate asserts `QcCompliance`. |
| `certificate_not_qualified` | `info` | The trusted list does not record the anchor's service as granted then, or a post-eIDAS certificate carries no `QcCompliance`. |
| `certificate_qualified_unknown` | `info` | No trusted list covers the anchor, so qualified status is not determined. Distinct from `certificate_not_qualified`. |
| `signature_timestamp_present` | `info` | The signature carries at least one `xades:SignatureTimeStamp`. What that is worth is decided by the token's own checks, folded in through `timestamp_verified`. |
| `signature_timestamp_absent` | `unknown` | It carries none, so nothing proves when it existed. |
| `timestamp_not_checked` | `skipped` | A timestamp uses a form this build does not process: an `Include`-style data selection, no decodable token, more than one token, or an unimplemented canonicalization algorithm. |
| `timestamp_token_parsed` | `passed` / `failed` | The token is (or is not) a CMS `SignedData` over an RFC 3161 `TSTInfo` within the size limit. |
| `timestamp_imprint_ok` | `passed` | The `messageImprint` matches the digest of the canonicalized `ds:SignatureValue`. |
| `timestamp_imprint_mismatch` | `failed` | It does not, or names a digest algorithm outside the allowlist. |
| `timestamp_signature_ok` | `passed` | The TSA's `SignerInfo` signature verified over its signed attributes. |
| `timestamp_signature_invalid` | `failed` | It did not, the signed attributes are missing or wrong, the token carries no single `SignerInfo`, or the named TSA certificate is not in the token. |
| `timestamp_tsa_certificate_ok` | `passed` | The TSA certificate carries a critical `extendedKeyUsage` of exactly `id-kp-timeStamping`. |
| `timestamp_tsa_certificate_invalid` | `failed` | It does not. |
| `timestamp_tsa_path_ok` | `passed` | The TSA certificate chains to a configured anchor at the token's `genTime`. |
| `timestamp_tsa_path_untrusted` | `failed` | It does not, under the same path rules as a signer chain. |
| `timestamp_tsa_path_unknown` | `unknown` | No trust anchors were configured. |
| `timestamp_before_signing_time` | `unknown` | The token's `genTime` precedes the claimed `xades:SigningTime` by more than the declared accuracy. Reported, never a failure: the claim is unauthenticated. |
| `timestamp_verified` | `passed` / `unknown` | Summarises one token in the signature's own check list, **excluding** its revocation checks, which are folded into the signature's verdict separately so they are counted once. `passed` only when every other check on that token passed or was informational; `unknown` for every other outcome, including a token that failed. Never `failed`: see [Verdicts](#verdicts). |
| `archive_timestamp_present` | `info` | An `xades:ArchiveTimeStamp` is present and is **not** validated. See [Archive timestamps](#archive-timestamps) for why M3 declined to implement the imprint rather than guess at it. Informational: an archive timestamp is evidence laid *on top of* a signature, so declining to re-verify it does not make the evidence already checked worth less. Omitted when none is present. |
| `dossier_timestamp_verified` | `info` | A dossier-level `es:TimeStamp` covered the elements the format mandates and its RFC 3161 token passed every check. Dossier level only. |
| `dossier_timestamp_invalid` | `failed` | A dossier-level `es:TimeStamp` contradicts the container: the imprint does not match, the token will not parse, the TSA signature does not verify, or the TSA certificate is not a timestamping certificate. Lowers the **dossier** verdict; every signature keeps its own. |
| `dossier_timestamp_not_checked` | `info` | A dossier-level `es:TimeStamp` could not be finished: no anchors, an unresolved `Include`, a scope the format mandates that it does not cover, a data-selection form this build does not implement, or no single decodable token. A gap, not a finding, so it does not block. |
| `document_timestamp_verified` | `info` | As `dossier_timestamp_verified`, for a `es:TimeStamp` inside one `es:Document`. The message names the document index. |
| `document_timestamp_invalid` | `failed` | As `dossier_timestamp_invalid`, per document. |
| `document_timestamp_not_checked` | `info` | As `dossier_timestamp_not_checked`, per document. |

### Verdicts

Per signature: `invalid` when any check is `failed`; otherwise `indeterminate`
when any check is `unknown` or `skipped`; otherwise `valid`. A check with status
`info` never blocks. The dossier verdict is the worst of the per-signature
verdicts — `invalid` worse than `indeterminate` worse than `valid` — and
`indeterminate` when there are no signatures, because there is nothing to be
valid. The terminology follows ETSI EN 319 102-1: `valid` is TOTAL-PASSED,
`invalid` is TOTAL-FAILED, and `indeterminate` is INDETERMINATE.

Reaching `valid` therefore needs, in practice: a structurally sound signature
whose references and signature value verify under the pinned policy, a signed
`SigningCertificate` property binding the certificate, a path to a configured
anchor at the validation time, a fully verified `xades:SignatureTimeStamp`
(without one, `signature_timestamp_absent` is `unknown` and blocks — nothing
proves when the signature existed), and fresh non-revoked status for every
non-anchor certificate on both the signer's and the TSA's chains. It also
needs **every modelled document covered by a signature that verified**: a
dossier carrying a document nothing signs, or one whose coverage could not be
determined, is capped at `indeterminate` by `documents_uncovered` or
`documents_coverage_undetermined`, however sound its other signatures are.
See [Document coverage](#document-coverage) for why.

It does **not** need the dossier to carry nothing else. Evidence a signature
carries beyond that minimum — unsigned qualifying properties this build does
not validate, an `xades:ArchiveTimeStamp`, a container `es:TimeStamp` this run
could not finish checking — is reported as `info` and does not block, because
none of it can make what was checked worth less. Nor does a revocation dated
after a validation time a verified timestamp proves.

The one container-level exception runs the other way. A container
`es:TimeStamp` whose imprint does not match the elements it names, or whose
token does not parse or verify, is evidence that the *container* was altered
after it was stamped. That is a finding, so `dossier_timestamp_invalid` and
`document_timestamp_invalid` are `failed` and make the **dossier** verdict
`invalid`. They never touch a signature's own checks or verdict: the JSON keeps
"this signature verifies" and "this container has been tampered with" apart,
because they are different questions with different answers.

Everything else a container timestamp produces stays off the verdict entirely.
A revocation answer nobody could obtain for its timestamp authority, a TSA
chain that reaches no configured anchor, a data-selection form this build does
not implement: all of those are recorded **on the timestamp's own entry** in
`data.timestamps[]`, with its own `checks` and `verified: false`, and surface
at the dossier level only as `dossier_timestamp_not_checked` or
`document_timestamp_not_checked` (`info`) naming the cause. They are never
emitted as blocking dossier-level checks.

That is not a convenience. A container timestamp is evidence laid *on top of*
the signatures, and a dossier that carries one it could not finish checking has
strictly more evidence than one that carries none — so letting it produce a
worse verdict than the empty dossier would be exactly backwards. Concretely,
the aggregation is:

- **`valid`** when every signature is `valid` and nothing else failed;
- **`invalid`** when any signature is `invalid`, or a container timestamp's
  imprint or token contradicts the container;
- **`indeterminate`** otherwise, which includes a dossier whose every
  signature is `valid` but which holds a document no signature covers, and one
  that carries a signature at a placement this build does not support.

One class of signature is deliberately excluded from that fold: a signature
whose only failure is `sig_placement_invalid`. Its own entry keeps the failed
check, but the dossier hears about it through `signatures_unsupported`
(`unknown`) instead, because a nesting this build does not implement is
missing support rather than evidence against anything. See
[the support boundary](#the-support-boundary).

**Only checks about the signature itself can make it `invalid`:** the
reference digests, the signature value, the algorithm policy, the reference
scope, the `SigningCertificate` binding, and the signer's own certificate
path. A signature timestamp is different. A token that does not verify — for
any reason, from a malformed token to a TSA chain that reaches no anchor —
supplies no proof that the signature existed at a given time. That is missing
information, not evidence against the signature, so under ETSI EN 319 102-1 it
yields INDETERMINATE rather than TOTAL-FAILED. Concretely: the token's own
`checks` keep their `failed` entries and its `verified` stays `false`, the
signature-level `timestamp_verified` is `unknown`, the validation time falls
back to `--at` or the clock, and the verdict is capped at `indeterminate`
unless something about the signature itself fails. A trust store that does not
know a timestamp authority's CA is a gap in the store, not a forged dossier.

The same reasoning makes `cert_path_search_exhausted` `unknown`: the tool
stopped looking rather than concluded.

A timestamp authority's own revocation status is the one thing excluded from
`timestamp_verified`, and only in one direction: an *unobtainable* revocation
answer does not stop a token from proving when the signature existed, because
letting it do so would quietly move the validation time back to "now" for a
reason unrelated to the timestamp. It still blocks the signature's verdict,
because the token's revocation check is folded into the signature's check list
in its own right. A TSA certificate that was actually revoked makes the check
`failed`, which sinks both.

## The create command

`create` is the only command that writes a dossier. It builds one unsigned
`es:Dossier` from files on disk, in the default e-Szignó 3.0 namespace, and
does nothing else: it signs nothing, and reads no dossier except the ones
`--embed` names. With `--encrypt-for` it also encrypts, which is the one
thing it does beyond writing XML; see
[Encrypting for a recipient](#encrypting-for-a-recipient). The writing
itself lives in `openszigno-author`, which never touches the filesystem;
`openszigno-core` stays read-only.

```sh
openszigno create --output FILE.es3 --title TITLE \
  [--document PATH[::TITLE[::MIME]]]... [--zip] [--embed DOSSIER.es3]... \
  [--encrypt-for CERT]... [--legacy-key-transport] \
  [--created RFC3339] [--json]
```

### What it writes

The layout is fixed. A dossier with one text document is exactly this, with
the payload Base64 on one line:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <es:DossierProfile Id="dossier" OBJREF="documents">
    <es:Title>Synthetic created dossier</es:Title>
    <es:E-category>electronic dossier</es:E-category>
    <es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate>
  </es:DossierProfile>
  <es:Documents Id="documents">
    <es:Document>
      <es:DocumentProfile Id="profile0" OBJREF="obj0">
        <es:Title>hello.txt</es:Title>
        <es:E-category>electronic data</es:E-category>
        <es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate>
        <es:Format><es:MIME-Type type="text" subtype="plain" extension="txt"/></es:Format>
        <es:SourceSize sizeValue="54" sizeUnit="B"/>
        <es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform>
      </es:DocumentProfile>
      <ds:Object Id="obj0">SGVsbG8gLi4uCg==</ds:Object>
    </es:Document>
  </es:Documents>
</es:Dossier>
```

`tests/fixtures/created.es3` is that output for the two committed inputs
under `tests/fixtures/create/`, and the golden matrix rebuilds it on every
run.

| Element | Value |
| --- | --- |
| `es:DossierProfile` | `Id="dossier"`, `OBJREF="documents"`, so the profile resolves to the one `es:Documents` element. |
| `es:E-category` | `electronic dossier` on the dossier, `electronic data` on every document. Not configurable. |
| `es:CreationDate` | `--created`, normalised to RFC 3339 UTC seconds, on the dossier and on every document alike. Without `--created` it is the current time in the same form, which is the only thing that makes two runs differ. |
| `es:DocumentProfile` | `Id="profile<index>"`, `OBJREF="obj<index>"`, indexes counted from 0 in the order the documents were given. |
| `es:MIME-Type` | `type`, `subtype`, and `extension`, the three attributes the reader reads. No `charSet` is written. |
| `es:SourceSize` | The decoded length in bytes, `sizeUnit="B"`, always present. |
| `es:BaseTransform` | `base64`, or `zip` then `base64` under `--zip`; `--encrypt-for` inserts `encrypt` before `base64`. |
| `ds:Object` | `Id="obj<index>"`, holding the Base64 payload with no line breaks. |

### Determinism

The same inputs with the same `--created` produce a byte-identical file.
Element order, indentation, and the identifiers above are fixed, no
identifier is random, Base64 is unwrapped, and the ZIP a `--zip` document
carries pins its member's modification time to the ZIP epoch. Only the
default creation date depends on the clock.

**`--encrypt-for` gives that up, by design.** An encrypted document carries a
content-encryption key, an initialisation vector, and key-transport padding
that must all be unpredictable, so two runs over the same inputs with the
same `--created` produce different bytes. A fixed value anywhere in that list
would make every document this tool wrote readable by anyone who read the
source. Without `--encrypt-for` nothing in the writer consults a random
source and the guarantee above is unchanged.

### Documents

`--document PATH[::TITLE[::MIME]]` names one document, and is repeatable.
`--embed DOSSIER.es3` names one existing dossier to embed, and is repeatable
too. Documents are written in the order given, every `--document` first and
every `--embed` after them.

| Part | Default |
| --- | --- |
| `TITLE` | The file's basename. It becomes `es:Title`, and it is the name `extract` writes the payload under. |
| `MIME` | The `type/subtype` registered for the title's extension. A title whose extension has no registered type is refused as `unknown_mime_type` rather than guessed; pass the type to write it anyway. |

The declared `extension` is the title's own suffix, when that suffix is a
short ASCII alphanumeric one; otherwise no extension is declared and the
reader falls back to content sniffing.

Titles are written in one canonical Unicode composition (NFC), the same one
the extraction sanitizer writes a filename in, so the title in the dossier
and the name the payload comes back out under are the same string.

A title is checked against exactly the rules
[Extraction policy](#extraction-policy) applies before writing a file, using
one shared implementation in `openszigno-author`. A title `extract` would
refuse is `unsafe_document_title` here, so a created dossier is always
extractable.

`--zip` stores every `--document` payload as `zip -> base64`, in a
one-member archive named with the same canonical title `es:Title` carries,
trimmed and in NFC, because `extract` names the file it writes from the
archive member. An embedded dossier is always
stored as `base64`, and is never encrypted either. A payload that deflates
better than `max_zip_compression_ratio` is refused as `zip_ratio_limit`,
because the reader would refuse to expand it.

An `--embed` file is parsed before it is embedded, so `create` never writes
an embedded document this tool cannot read back; a file that does not parse
fails with the structural code the parser produced. It is titled
`<stem>.dosszie` and declared `application/nldossier2`, which is what makes
`list` report it as a nested dossier and `extract` expand it.

### Encrypting for a recipient

`--encrypt-for CERT` encrypts every `--document` payload as a CMS
`EnvelopedData` addressed to that certificate, which is exactly the form
[Decryption](#decryption) reads back. It is repeatable: every recipient gets
its own `KeyTransRecipientInfo`, so any one of their private keys recovers
the document, and `extract --decrypt-key` reports `decrypted: true`.

An `--embed` dossier is **not** encrypted. It stays `base64`, so `list` can
still report what is inside it and the documents within keep whatever
transforms they already carry. Encrypting a whole nested dossier would hide
its structure behind one opaque blob for no gain, since its own documents can
be encrypted individually before they are embedded.

The transform chain is written in the forward order the specification fixes,
which the reader reverses:

| Flags | `es:BaseTransform` | What is encrypted |
| --- | --- | --- |
| `--encrypt-for` | `encrypt`, `base64` | The document bytes. |
| `--encrypt-for --zip` | `zip`, `encrypt`, `base64` | The one-member ZIP archive: the plaintext of the CMS message *is* the ZIP, and the reader expands it after decrypting. |

`es:SourceSize` stays the plaintext length in both cases, because that is
what the reader compares the fully decoded bytes against.

What is written, and nothing else:

| Layer | Written |
| --- | --- |
| Container | A bare DER `ContentInfo` with `id-envelopedData` (RFC 5652 §6), version 0. No MIME wrapper. |
| Recipient | One `KeyTransRecipientInfo` per `--encrypt-for`, version 0, named by `issuerAndSerialNumber`. Every certificate can be named that way, whereas `subjectKeyIdentifier` needs an extension a certificate need not carry; the reader accepts both. |
| Key transport | RSAES-OAEP with SHA-256 and MGF1-SHA-256 and the default empty label. `--legacy-key-transport` writes RSAES-PKCS1-v1_5 instead. |
| Content encryption | AES-256-CBC, with a fresh content-encryption key and initialisation vector for every document. |

**DES-EDE3-CBC is never written.** The reader accepts it behind
`--allow-legacy-ciphers` because real dossiers carry it, which is a reason to
read it and not a reason to produce more of it.

`--legacy-key-transport` exists for interoperability with a reader that
cannot do OAEP. What the sources in this repository actually establish about
the Microsec reference tool is narrower than the flag's name suggests: its
documented `-encryptor_symm_alg` option takes OpenSSL cipher names and
defaults to `des-ede3-cbc`, which is a statement about the *content* cipher
only. No source available here says which key transport it writes, and it
documents no option to choose one. RSAES-PKCS1-v1_5 is what an OpenSSL CMS
backend produces for `rsaEncryption` unless OAEP is asked for explicitly, so
it is the likely default, but that is inference and not evidence. Prefer
RSAES-OAEP; reach for the flag only when something on the other side has
actually refused an OAEP message.

Recipient certificates are public material, so unlike a decryption key they
are read with the ordinary bounded reader; each is capped at 1 MiB. Nothing
derived from one reaches the envelope, and a refusal names the recipient by
its position on the command line and never by path or by subject. **No key
material of any kind is written or reported**: the content-encryption key
exists only inside the process and is zeroed when it is dropped, and
`create` never reads a private key at all.

| Situation | Result |
| --- | --- |
| The certificate is not readable X.509, in DER or in a PEM `CERTIFICATE` block, or is over 1 MiB | `invalid_recipient_certificate`, exit 4. |
| The certificate carries a public key that is not RSA | `unsupported_recipient_key`, exit 4. |
| The RSA key is too small to wrap a 32-byte content key under the chosen transport | `unsupported_recipient_key`, exit 4. |
| The certificate has expired | `recipient_certificate_expired` **warning**, exit 0, and the document is encrypted for it anyway. |
| The file cannot be opened or read | `io_error`, exit 3, as for `--document`. |

Expiry is a warning and not a refusal because nothing in the format or in the
reader consults a recipient certificate's validity: the private key still
unwraps the content key the day after the certificate lapses, and refusing
would make a legitimate "encrypt this for the key I hold" impossible. The
warning says the operator should check they meant it. Nothing else about the
certificate is checked either: `create` builds no path, checks no revocation,
and asserts nothing about who the recipient is. Encrypting says who can read
a document; it says nothing about who wrote it, and the dossier is still
unsigned.

### Writing the output

The output file is created with `O_EXCL` through the same descriptor-relative
machinery `extract` uses, so the same rules hold: an existing destination is
`output_exists`, a path component that is a symlink or is not a directory is
`unsafe_output_directory`, and missing parent directories are created. The
whole dossier is rendered in memory and checked before the file is created,
and a failed write removes what this run created, so a run either writes a
complete dossier or leaves the destination untouched.

Every [limit](#limits) that bounds reading bounds writing too: the document
count, one document's decoded size, the aggregate decoded size, the Base64
character count, and the ZIP compression ratio.

### The JSON shape

`input` describes the format, not a file that was read: `format` is
`"microsec-es3"`, the format this command writes, and `bytes` is `null`
because `create` reads no dossier. On failure both are `null`, as they are
for every other command whose input could not be used.

| `data` field | Type | Meaning |
| --- | --- | --- |
| `output` | string | The output path exactly as the caller gave it. It is never resolved or made absolute. |
| `bytes` | number | The size of the file written. |
| `created` | string | The creation date written, RFC 3339 UTC seconds. |
| `documents` | array | One entry per document written, in source order. |

| `documents[]` field | Type | Meaning |
| --- | --- | --- |
| `index` | number | Position in the dossier, from 0. |
| `title` | string | The `es:Title` written. |
| `mime_type` | object | `media_type`, `subtype`, `extension`, `charset`, as `list` reports them. `charset` is always `null`. |
| `source_size` | number | The decoded length declared in `es:SourceSize`. |
| `transforms` | array | `["base64"]`, or `["zip", "base64"]`; with `--encrypt-for`, `["encrypt", "base64"]` or `["zip", "encrypt", "base64"]`. |
| `nested_dossier` | boolean | Whether the declared type marks the document as an embedded dossier. |
| `encrypted` | boolean | Whether the payload was written as a CMS `EnvelopedData`, so that only a recipient's private key can read it back. `false` for every document without `--encrypt-for`, and for every `--embed` dossier. |
| `object_ref` | string | The `ds:Object` `Id`, which is also the `extract --document` selector for it. |

Every successful run warns `created_dossier_unsigned`. Creating a dossier
proves nothing about its contents, and the envelope says so on every run.

## The sign command

`sign` writes a signed copy of a dossier. It is the only command that produces
a signature, and it is not the command that judges one: producing a signature
and checking one are different operations, and this tool keeps them in
different commands on purpose. Every successful run warns
`signed_dossier_unverified`.

```sh
openszigno sign FILE.es3 --output SIGNED.es3 --key KEY.pem --cert CERT.pem \
  [--passphrase-file F] [--chain CA.pem]... [--scope document|dossier] \
  [--document SELECTOR]... [--tsa URL] [--tsa-cert CERT]... \
  [--signing-time RFC3339] [--algorithm NAME] \
  [--online-allow-private] [--online-proxy URL] [--json]

openszigno sign FILE.es3 --output SIGNED.es3 --csc CONFIG.toml \
  [--csc-credential ID] [the same --scope/--document/--tsa/... flags] [--json]
```

The signing itself lives in `openszigno-author`, which reads no file and opens
no socket: the CLI reads the dossier and the key material, reaches the private
key through the `Signer` trait, and carries every RFC 3161 request to the
timestamp authority itself. That split is what makes a remote signing backend
a matter of implementing one trait, and `--csc` is the second implementation
of it; see [Signing through a CSC service](#signing-through-a-csc-service) and
[remote-signing.md](remote-signing.md).

### What it writes

One `ds:Signature` per signature, placed where the e-dossier format puts it:
inside the `es:Document` for `--scope document`, and as a direct child of
`es:Dossier` for `--scope dossier`. This is the shape, with the Base64 values
trimmed:

```xml
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="sig-doc0">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference Id="ref-sig-doc0-object" URI="#obj0">
      <ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue>a7MWc68BhZJ5YGEE...</ds:DigestValue>
    </ds:Reference>
    <ds:Reference Id="ref-sig-doc0-document-profile" URI="#profile0">...</ds:Reference>
    <ds:Reference Id="ref-sig-doc0-signature-profile" URI="#profile-sig-doc0">...</ds:Reference>
    <ds:Reference Id="ref-sig-doc0-signed-properties" URI="#signed-props-sig-doc0"
                  Type="http://uri.etsi.org/01903#SignedProperties">...</ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>h3Gu+iByx4xAmcZr...</ds:SignatureValue>
  <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIC+TCC...</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
  <ds:Object Id="profile-sig-doc0">
    <es:SignatureProfile xmlns:es="https://www.microsec.hu/ds/e-szigno30#" Id="sigprof-sig-doc0">
      <es:Type>signature</es:Type><es:Generator>openSzigno</es:Generator>
    </es:SignatureProfile>
  </ds:Object>
  <ds:Object Id="xades-sig-doc0">
    <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="#sig-doc0">
      <xades:SignedProperties Id="signed-props-sig-doc0">
        <xades:SignedSignatureProperties>
          <xades:SigningTime>2026-01-02T00:00:00Z</xades:SigningTime>
          <xades:SigningCertificateV2><xades:Cert><xades:CertDigest>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>+cSXgp1X6XtBY5rx...</ds:DigestValue>
          </xades:CertDigest></xades:Cert></xades:SigningCertificateV2>
        </xades:SignedSignatureProperties>
        <xades:SignedDataObjectProperties>
          <xades:DataObjectFormat ObjectReference="#ref-sig-doc0-object">
            <xades:MimeType>text/plain</xades:MimeType>
          </xades:DataObjectFormat>
        </xades:SignedDataObjectProperties>
      </xades:SignedProperties>
      <xades:UnsignedProperties><xades:UnsignedSignatureProperties>
        <xades:SignatureTimeStamp>
          <xades:EncapsulatedTimeStamp>MIIF...</xades:EncapsulatedTimeStamp>
        </xades:SignatureTimeStamp>
        <xades:CertificateValues>
          <xades:EncapsulatedX509Certificate>MIID...</xades:EncapsulatedX509Certificate>
        </xades:CertificateValues>
      </xades:UnsignedSignatureProperties></xades:UnsignedProperties>
    </xades:QualifyingProperties>
  </ds:Object>
</ds:Signature>
```

### What each reference covers, and why

The reference set is not a choice: it is what
[Reference scope](#reference-scope) requires the verifier to insist on, so
writing anything less produces a signature this tool would refuse.

| Placement | References written |
| --- | --- |
| `document` | the document's payload `ds:Object`, its `es:DocumentProfile`, the signature's own profile object, and the `xades:SignedProperties`. |
| `dossier` | `/es:Dossier/es:DossierProfile`, `/es:Dossier/es:Documents`, the signature's own profile object, and the `xades:SignedProperties`. |

Every reference is same-document (`#id`), carries exactly one transform,
Exclusive XML Canonicalization 1.0, and is digested with SHA-256, and
`ds:SignedInfo` is canonicalized the same way. There is no
enveloped-signature transform anywhere, and there is nothing to remove: every
reference names a sibling of the signature or a child of it, so no reference's
node set ever contains the signature it is written in. That is also why the
`xades:SignedProperties` and the signature-profile object each get a reference
of their own rather than riding along inside a `URI=""` one, which would
cover neither.

The `xades:SignatureTimeStamp` is the one exception to "exclusive
everywhere". It covers the canonicalized `ds:SignatureValue` **element**, and
because the element this build writes names no `ds:CanonicalizationMethod`,
XAdES clause 7.1.4.3.1 makes inclusive C14N 1.0 the default for it. The
signer computes the inclusive form for exactly that reason: the two differ by
the ancestor namespace declarations `ds:SignatureValue` does not visibly use,
and a token over the wrong one is a token nobody recomputes.

### Identifiers and determinism

| Element | `Id` |
| --- | --- |
| `ds:Signature` | `sig-doc<N>` for document scope, `sig-dossier` for dossier scope. |
| the signature-profile `ds:Object` | `profile-<signature id>`. |
| the qualifying-properties `ds:Object` | `xades-<signature id>`. |
| `xades:SignedProperties` | `signed-props-<signature id>`. |
| each `ds:Reference` | `ref-<signature id>-<what it covers>`. |

No identifier is random. One already in use in the dossier is disambiguated
rather than allowed to collide: the signature's `Id` gains a `-2`, `-3` and so
on until every identifier the new signature would introduce is free, and every
identifier derived from it follows (`sig-doc0-2`, `signed-props-sig-doc0-2`,
`ref-sig-doc0-2-object`). That is what makes co-signing work; see
[Signing a dossier that is already signed](#signing-a-dossier-that-is-already-signed).
A dossier that has exhausted 64 variants of one base identifier is
`document_already_signed`. Given the same input, key, signing time and flags,
**RSA PKCS#1 v1.5 produces byte-identical output**: the signature is a
deterministic function of what it signs. RSA-PSS salts its input and ECDSA
draws a nonce, so those two do not, and `--signing-time` is what pins the one
other moving part; without it the current time is written.

A dossier declared ISO-8859-2 is decoded to UTF-8 before it is signed and its
declaration is rewritten to say so. That changes no signature already in the
file: canonical XML is UTF-8 whatever the source encoding was, so every
existing digest is computed over exactly the same octets as before. The
declaration is read by the reader's own parser
(`openszigno_core::declared_encoding`), so every spelling the reader accepts
is one the writer rewrites: either quote character, and any whitespace around
the `=`. Only the encoding label's own bytes are replaced.

### Nothing outside a signature is ever rewritten

A signature is written as a skeleton and completed in three passes (reference
digests, then the signature value, then the timestamp token), because each
stage's input only exists once the previous one is in the document. The values
stand in as placeholder strings until their pass fills them in.

Every substitution is bounded to the byte range of the `ds:Signature` element
that wrote the placeholder, taken from the parsed working document. The
dossier's own text is never touched, whatever it happens to say: a document
whose title or payload reads exactly like a placeholder is content, it is
digested as it stands, and it comes back out of `list` unchanged. A
substitution over the whole document would rewrite it after its digest had
been taken, and produce a dossier `sign` called a success and `verify` then
reported `reference_digest_mismatch` for.

The ranges never overlap, because no signature this tool writes ever contains
another, and they are applied last first so that the earlier ones stay valid
as lengths change.

### Nothing the dossier says decides what is signed

Some of the values in a signature come out of the dossier rather than out of
this tool: the `Id` and `OBJREF` attributes a `ds:Reference` points at, the
declared media type an `xades:DataObjectFormat` carries, and the root
namespace the signature-profile object declares. A dossier is untrusted input,
and every digest is computed *after* those values are in the document, so a
value that reached the XML unescaped would let the dossier write the reference
set and the signed properties rather than describe them, under the operator's
own key.

Two rules hold, and both are enforced:

- **Refusal.** An `Id` or `OBJREF` that is not an XML
  [NCName](https://www.w3.org/TR/xml-names/#NT-NCName), a declared media type
  outside the characters `create` itself allows a media type (both halves
  non-empty, at most 64 characters, ASCII alphanumerics and `.-+_`), and a
  namespace URI holding `<`, `>`, `"`, `'`, `&` or a control character are all
  `document_not_signable`, before anything is rendered. The refusal names the
  attribute, never its value.
- **Escaping.** Every remaining interpolation goes through the same attribute
  and text escapers the unsigned writer uses, so no dossier-derived string can
  reach signature XML unescaped whatever a later change adds to the rendering.

### Algorithms

| `--algorithm` | `ds:SignatureMethod` | Deterministic |
| --- | --- | --- |
| `rsa-sha256` (default for an RSA key) | `...xmldsig-more#rsa-sha256` | Yes |
| `rsa-pss-sha256` | `...2007/05/xmldsig-more#sha256-rsa-MGF1` | No |
| `ecdsa-p256-sha256` (default for a P-256 key) | `...xmldsig-more#ecdsa-sha256` | No |

RSA PKCS#1 v1.5 with SHA-256 is the default rather than PSS because it is what
Hungarian e-akta verifiers universally accept. All three are inside the pinned
[algorithm policy](#algorithm-policy) `verify` enforces, and an ECDSA
signature is written as the raw `r || s` pair XMLDSig prescribes.

### Timestamping

`--tsa URL` posts an RFC 3161 `TimeStampReq` (`application/timestamp-query`,
SHA-256 imprint, `certReq` set, no nonce) for each signature, and embeds the
token it gets back as an `xades:SignatureTimeStamp` with the implicit data
selection. It is the only thing that makes `sign` open a socket, and it goes
through the same transport `verify --online` uses: the same destination
policy (`http`/`https` only, no userinfo, and no loopback, private,
link-local or unique-local address without `--online-allow-private`), the
same address pinning, the same timeouts, the same refusal to follow a redirect
to another host, and no proxy from the environment.

The answer is checked for the two things a caller cannot check: that it is a
granted response carrying a token, and that the token stamps the imprint that
was asked about. Anything else is `tsa_failed`, the output file is never
written, and nothing partial is left behind. A token is embedded evidence, not
a verified one: only `verify` checks a timestamp's signature, its authority's
`extendedKeyUsage`, and its path.

A signing time later than the token's `genTime` is worth avoiding: `verify`
reports `timestamp_before_signing_time` for it, which leaves the token
unverified. `--signing-time` should not be in the future.

### Signing through a CSC service

`--csc CONFIG.toml` replaces the local key with a Cloud Signature Consortium
API v2 service, so a qualified certificate held by a remote signature creation
device, or in an EUDI Wallet, signs the same XAdES structure the software
signer produces. **Only the digest ever leaves the machine.** The dossier, the
payloads and the titles stay where they are; what is sent is one base64
SHA-256 digest of the canonicalised `ds:SignedInfo` per signature, the
credential identifier, and a bearer token in an `Authorization` header.

The backend is a second implementation of the same `Signer` trait
`SoftwareSigner` implements, and it reports `prefers_digest() == true`, so the
author crate hands it the digest instead of the octets. Nothing about what a
signature covers, where the element sits, or what it digests changes.

#### The request sequence

Discovery runs before the dossier is touched, because the signing certificate
has to exist before a `ds:SignedInfo` can be built: `xades:SigningCertificateV2`
digests it, so there is nothing to sign until it is in hand.

| Step | Request | What it settles |
| --- | --- | --- |
| 1 | `POST info` | `specs`, `methods`, `supportsRar`, `supportedHashTypes` and `signAlgorithms`. A `1.x` service, or one that will not sign a data-to-be-signed representation, stops the run here. |
| 2 | `POST credentials/list` | Only when no credential was named. Exactly one is taken; several is `csc_credential_ambiguous` with the identifiers. |
| 3 | `POST credentials/info` | With `certificates: "chain"` and `certInfo: true`: the signing certificate, the rest of the chain, the key's algorithms and the authorisation mode. |
| 4 | `POST credentials/authorize` | Once per signature, with `numSignatures: 1`, the real digest, `hashAlgorithmOID` `2.16.840.1.101.3.4.2.1`, and `PIN`/`OTP` from the files the configuration names. Answers with Signature Activation Data. |
| 5 | `POST signatures/signHash` | The credential, the SAD, the same hash, and `signAlgo` with `signAlgoParams` where the scheme needs them. |

The real hashes go into step 4, never placeholders, and `numSignatures` is the
count actually being produced: a SAD that is not bound to the data it covers
authorises signing anything for its lifetime.

The chain from step 3 becomes `xades:CertificateValues`, so `--chain` stays
optional for a CSC run: the service already published what a verifier needs to
build the path.

#### Discovery is read, never assumed

The three deployments surveyed in
[remote-signing.md](remote-signing.md#35-sandboxes-reached-directly) disagree
on every discovery field: `supportedHashTypes` is the keyword `dtbsr` on one
service and the SHA-256 OID on another, `supportsRar` is true on one and false
on the next, and `specs` ranges over `2.1.0.1` and `2.2.0.0`. No vendor profile
is compiled in. `supportedHashTypes` is accepted when it is `dtbsr`, when it is
the SHA-256 OID, and when it is absent: an early v2 service signed digests and
nothing else.

The algorithm is chosen from the credential's own `key/algo` list, because
`ds:SignatureMethod` in the document has to agree with what the service
actually did and only the credential knows that. A scheme OID beats a bare key
OID; RSASSA-PSS is last of the RSA candidates for the same reason PKCS#1 v1.5
is the local default, and is refused outright when the service published no
`signAlgoParams` for it.

| Credential `key/algo` | Written as | `signAlgo` sent |
| --- | --- | --- |
| `1.2.840.113549.1.1.11` sha256WithRSA | `rsa-sha256` | the same OID |
| `1.2.840.113549.1.1.1` rsaEncryption | `rsa-sha256` | the same OID |
| `1.2.840.10045.4.3.2` ecdsa-with-SHA256 | `ecdsa-p256-sha256` | the same OID |
| `1.2.840.10045.2.1` ecPublicKey | `ecdsa-p256-sha256` | `1.2.840.10045.4.3.2` |
| `1.2.840.113549.1.1.10` RSASSA-PSS | `rsa-pss-sha256` | the same OID, with `signAlgoParams` |

An ECDSA signature comes back as either the DER `SEQUENCE` or the fixed-width
`r || s` pair, depending on the vendor; both are accepted and XMLDSig's raw
pair is what gets written.

#### The returned signature is verified before anything is written

A service in `dtbsr` mode signs the digest it was handed and never sees the
document, so a canonicalisation mistake yields a syntactically perfect
signature over the wrong bytes, and that failure is invisible until somebody
verifies it. So the returned signature is checked locally against the
certificate the service published, before the signed dossier reaches the
filesystem. A signature that does not verify is `csc_signature_invalid` and no
file is written. This is not a courtesy check; it is the reason a CSC run can
be trusted to have produced what it says it produced.

#### The transport

Every request goes through the same `online` transport `verify --online`
fetches revocation data with: the same destination policy, the same address
pinning, the same connect and total timeouts, the same refusal to follow a
redirect to another host, a 256 KiB response cap, and no proxy from the
environment. `https` is required unless `--online-allow-private` is given,
because the bearer token travels in a request header and plaintext hands it to
anyone on the path; that same flag is what permits a loopback service, which
is how this project's own test suite serves a mock.

The token is put in the `Authorization` header and nowhere else. It is not in
a URL, not in a body, not in a message, not in a warning and not in the JSON
envelope. A refusal quotes the HTTP status and the service's own `error`
string; `error_description` is free text a provider writes and is never
printed.

#### The configuration file

A small, flat TOML table. openSzigno reads a deliberately narrow subset
(comments, blank lines, and `key = "value"` with a basic or literal string)
and refuses a table header, an array, a number or a bare value by name rather
than ignoring it.

```toml
base_url = "https://qtsp.example/csc/v2"
client_id = "openszigno-cli"
access_token_file = "token"   # or access_token = "..."
credential_id = "cred-1a2b3c" # optional; --csc-credential overrides it
pin_file = "pin"              # explicit-mode authorisation
```

| Key | Meaning |
| --- | --- |
| `base_url` | Required. The CSC API base, ending in `/csc/v2`. One trailing slash is trimmed. |
| `client_id` | Required. The OAuth 2.0 client the token was issued to. |
| `access_token`, `access_token_file` | Exactly one is required: the `scope=service` bearer token, obtained out of band. |
| `credential_id` | Optional. `--csc-credential` overrides it. |
| `pin_file`, `otp_file` | Optional. Read only for an `explicit`-mode credential. |
| `client_secret`, `client_secret_file`, `redirect_uri` | Accepted and reserved for the interactive `csc login` flow; each earns a `csc_key_unused` warning. A `redirect_uri` that is not a loopback URI is refused. |

A relative secret path is resolved against the configuration file's own
directory, and one trailing line ending is stripped. Permissions are not
enforced, because a mode this tool refused would be a mode somebody worked
around, but a world-readable file earns `csc_config_permissive`.

#### What is not implemented

A credential whose authorisation mode is `oauth2` needs a second OAuth 2.0
authorization-code round with `scope=credential`, which needs a browser and a
loopback redirect listener. This round is deliberately non-interactive, so such
a credential is `csc_authorization_required` and the message names the flow to
complete. RFC 9396 `authorization_details`, which `supportsRar` advertises,
belongs to that same interactive flow: it is read from `info` and reported, and
building it is part of the follow-up `openszigno csc login` work.

CSC v1 is not supported. `info` reports `specs`, so a v1 service is detected
and refused with a clear message rather than half-supported.

### Signing a dossier that is already signed

A second signature can be added to a dossier that already carries one, and a
document that already has a signature can be given another: neither
signature's references reach inside the other, so nothing that verified stops
verifying. Co-signing a document this tool has already signed works too — the
identifiers are disambiguated, as
[Identifiers and determinism](#identifiers-and-determinism) describes, and the
first signature is not read, not rewritten and not removed.

Three cases are refused with `document_already_signed`, because writing them
would silently break what is already there:

- adding a document signature to a dossier that carries a dossier-level
  signature or a dossier-level `es:TimeStamp`, both of which cover
  `es:Documents` and would stop matching the moment a document changes;
- adding anything to a dossier carrying a signature with a `URI=""`
  reference, which covers everything outside itself;
- adding a signature to an element an existing `ds:Reference` already
  resolves to, or to an element inside one. Adding a `ds:Signature` changes
  the canonical form of its container and of every ancestor of that
  container, so such a reference would stop matching: an `es:Document` with an
  `Id` of its own, referenced by `URI="#doc0"`, is the shape this catches.
  Only the same-document `#id` form is resolved, and a reference this tool
  cannot resolve may name anything, so it counts as covering rather than
  being assumed harmless.

Nothing this tool writes falls into any of the three, so the limitation is
about dossiers from elsewhere. `sign` never rewrites or removes a signature.

### The JSON shape

| `data` field | Type | Meaning |
| --- | --- | --- |
| `output` | string | The output path exactly as the caller gave it. It is never resolved or made absolute. |
| `bytes` | number | The size of the file written. |
| `signatures` | array | One entry per signature written, in the order written. |

| `signatures[]` field | Type | Meaning |
| --- | --- | --- |
| `id` | string | The `Id` of the `ds:Signature` element. |
| `scope` | string | `document` or `dossier`. |
| `document_index` | number or null | The index of the document the signature sits in; `null` for dossier scope. |
| `algorithm` | string | The `--algorithm` name actually used. |
| `signing_time` | string | The `xades:SigningTime` written, RFC 3339 UTC seconds. |
| `timestamped` | boolean | Whether an `xades:SignatureTimeStamp` was embedded. It says a token was obtained, never that it was verified. |
| `signer` | string | Which backend produced the signature: `software` for `--key`, `csc` for `--csc`. |
| `credential_id` | string | `--csc` runs only: the CSC credential that signed. Not a secret; the bearer token never appears. |
| `csc_specs` | string | `--csc` runs only: the `specs` version the service reported from `info`. |

### Writing the output

The output file is created with `O_EXCL` through the same
descriptor-relative machinery `create` and `extract` use, so the same rules
hold: an existing destination is `output_exists`, a path component that is a
symlink or is not a directory is `unsafe_output_directory`, and a failed write
removes what this run created rather than leaving a half-written file that
looks like a signed dossier.

### Key material

`--key`, `--cert` and `--passphrase-file` are files, and the passphrase may
alternatively come from `OPENSZIGNO_DECRYPT_PASSPHRASE`, the same variable
`extract --decrypt-key` reads, because a second variable would be a second
place for a secret to be left set. Nothing comes from `argv`. Key bytes, the
passphrase, and anything derived from either never appear in a message, a
warning, or the JSON envelope, and "wrong passphrase" is deliberately not told
apart from "not a PKCS#8 file". A certificate that does not belong to the key
is `signing_key_mismatch` and is refused before anything is signed.

## Extraction policy

- Decode Base64 as bytes, never by treating a dossier as locale-dependent
  text after the XML layer.
- Expand embedded dossiers recursively by default. A document flagged
  `nested_dossier`, or whose decoded bytes sniff as a dossier, is written as a
  payload file *and* parsed with the same options; its documents are extracted
  into a sibling subdirectory named after the payload file plus `.d`:

  ```text
  out/
    court.dosszie            # the embedded dossier, byte for byte
    court.dosszie.d/         # what it contains
      ruling.pdf
      annex.dosszie
      annex.dosszie.d/
        notice.html
  ```

  Subdirectories are created relative to the parent's directory descriptor
  with the same `mkdirat`/`openat` machinery as files on Unix. A nested parse
  failure never fails the run: it is reported as `nested_dossier_invalid` and
  the raw file is kept. `--no-recursive` disables expansion entirely.
- Derive an output extension from content sniffing only when the sanitised
  title has none and the dossier declares none; a declared extension always
  wins.
- Deduplicate repeated output names deterministically. Real dossiers reuse
  document titles, so when two planned outputs in the same directory fold to
  the same NFC-normalised, case-folded key, the first keeps its name and each
  later one gets `-<document index>` inserted before its extension
  (`ruling.pdf`, then `ruling-7.pdf`). A `<file>.d` subdirectory follows its
  payload file, so a renamed embedded dossier lands in `court-7.dosszie.d`;
  a directory name that clashes on its own is renamed by the same rule. Each
  rename is reported as `output_name_deduplicated`, naming the document index
  and its `dossier_path` only. Comparison stays case-insensitive. A renamed
  candidate that is itself taken — which a title crafted to spell it makes
  easy — does not end the run: the candidates keep counting,
  `ruling-7.pdf`, then `ruling-7-2.pdf`, `ruling-7-3.pdf` and on, up to 64
  candidates per name. Only a name still taken after all 64 is the residual
  error `output_name_collision`, which aborts the run with nothing written.
- All documents in the whole tree are decoded in memory and all output names,
  collisions, and destination existence are checked before the output
  directory is touched; a decode failure, an unsafe name, a collision, or a
  pre-existing destination file or subdirectory aborts with no files written.
- Derive output names from the document title only after sanitization.
  Reject empty titles, `.` / `..`, path separators, absolute paths, control,
  format, bidirectional, invisible, and private-use characters,
  non-ASCII-space whitespace, leading `.` or `-`, trailing `.` or space,
  reserved Windows device names, and over-long names. A declared MIME
  extension must be short and alphanumeric or the document is rejected; it
  is appended when the title does not already end with it. Names are
  NFC-normalised and collisions are detected case-insensitively on the
  normalised form.
- The output directory may be new or existing. Its path must not contain
  symlinks (or reparse points on Windows). A directory created by this run
  has mode `0700` on Unix; an existing directory keeps its mode.
- On Unix, the output path is opened one component at a time relative to
  the previous directory descriptor with `O_NOFOLLOW`, missing components
  are created relative to that descriptor, and files are created relative to
  the final descriptor with `O_CREAT|O_EXCL|O_NOFOLLOW` and mode `0600`. No
  component is ever resolved through a symlink, so swapping any part of the
  path for a link after the checks cannot redirect writes. On other
  platforms files are created by path with no-clobber semantics; the
  directory-swap race remains a residual risk there.
- Existing files are never overwritten. If creating or writing a later file
  fails, everything the same run created — files and the subdirectories it
  made, deepest first — is removed before the error is reported; the message
  says so if that clean-up itself fails.
- Restrict the run to `--document` selectors when any are given. Selection
  applies to the top level only, changes nothing about how a selected document
  is decoded, named, deduplicated, or expanded, and is reported back as
  `data.selected`. See [Selecting documents](#selecting-documents).
- Write a payload to stdout only when `--stdout` names exactly one decodable
  document, and then write nothing else to that stream. See
  [The payload stdout mode](#the-payload-stdout-mode).
- Enforce fixed limits for dossier bytes, document count, decoded bytes, ZIP
  member count, per-member bytes, total bytes, and compression ratio.
- Report document encryption, missing payload references, and unsupported
  transform chains explicitly. Decrypt an encrypted document only when
  `--decrypt-key` supplies a key, under the same limits and with the same
  no-clobber, all-or-nothing behaviour as any other document; see
  [Decryption](#decryption).

## Decryption

`extract --decrypt-key` reverses the `encrypt` transform. This is the M4
milestone. The other direction, `create --encrypt-for`, writes a deliberately
narrow subset of what is described here; see
[Encrypting for a recipient](#encrypting-for-a-recipient).

**Decryption is not verification and never becomes it**: reading a document
proves that a key could unwrap it, not that anybody signed it, and not that
the signer is who a certificate says. Every statement in
[Verification boundary](#verification-boundary) is unchanged by it, `verify` is
unaffected, and `signatures_verified` stays `false`.

### What `encrypt` is

The e-dossier specification (§3.2.1.1.6 in both the English v1.2 prose and the
Hungarian v1.5 PDF) says only:

> `encrypt`: S/MIME encryption (optional)

and adds that `es:RecipientCertificateList/es:RecipientCertificate` "may" list
the certificates whose private keys can decrypt the payload. It fixes no
algorithm, no recipient-identifier form, and no framing. That is the whole of
what the format specification says.

Microsec's own `eszigno3` reference CLI is the concrete evidence for what is
actually produced. It documents `cm_decrypt` as "RFC5652 szerinti CMS
titkosítás feloldása" — undoing CMS encryption per RFC 5652 — and
`export_recipient_infos` as exporting "the recipients' certificates and the
encrypted keys", which is the CMS `RecipientInfos` structure. Its
`-encryptor_symm_alg` option takes OpenSSL cipher names (`aes-128-cbc` and the
like) and **defaults to `des-ede3-cbc`**, and `-encryptor_key` takes a PEM or
PKCS#12 private key.

openSzigno therefore reads a decoded `encrypt` payload as a DER `ContentInfo`
(RFC 5652 §3) whose content type is `id-envelopedData` (`1.2.840.113549.1.7.3`).
This is what "S/MIME encryption" means in practice when the Base64 layer is
applied on top of it by the surrounding transform chain.

Two things could not be confirmed from any source available here and are
recorded as residuals in [roadmap.md](roadmap.md): whether any producer wraps
the CMS message in MIME headers instead of emitting bare DER, and whether
`RecipientIdentifier` is ever anything but `issuerAndSerialNumber` in the
wild. Both forms of the identifier are implemented; a MIME-wrapped payload
would be reported as `invalid_cms`.

### The supported subset

| Layer | Accepted |
| --- | --- |
| Container | `ContentInfo` with `id-envelopedData` (RFC 5652 §6). RFC 5083 `id-ct-authEnvelopedData` is recognised only to be skipped as unsupported. |
| Recipient | `KeyTransRecipientInfo` only, named by `issuerAndSerialNumber` or `subjectKeyIdentifier`. `kari`, `kekri`, `pwri`, and `ori` recipients are ignored when looking for a match. |
| Key transport | RSAES-PKCS1-v1_5 (`1.2.840.113549.1.1.1`) and RSAES-OAEP (`1.2.840.113549.1.1.7`) with MGF1 and SHA-1, SHA-256, SHA-384, or SHA-512. The OAEP hash and the MGF1 hash must agree, and only the default empty label is accepted. |
| Content encryption | AES-128-CBC, AES-192-CBC, AES-256-CBC. DES-EDE3-CBC only with `--allow-legacy-ciphers`. |

DES-EDE3-CBC is off by default because it is weak — a 64-bit block and an
effective strength far below its key length — and on behind a flag because it
is what the reference implementation encrypted with by default, so refusing it
outright would make real dossiers unreadable. The flag names the trade instead
of hiding it, exactly as `--allow-legacy-algorithms` does in `verify`.

### Key material

| Input | Where it comes from |
| --- | --- |
| Private key | `--decrypt-key FILE`: PKCS#8, DER or PEM, `PRIVATE KEY` or `ENCRYPTED PRIVATE KEY`. |
| Certificate | `--decrypt-cert FILE`, PEM or DER; or a `CERTIFICATE` block in a PEM key file. |
| Passphrase | `--decrypt-passphrase-file FILE`, or the environment variable `OPENSZIGNO_DECRYPT_PASSPHRASE`. The file wins when both are set. |

**No key or passphrase ever comes from the command line.** `argv` is readable
by other processes on most systems and lands in shell history, so there is no
`--decrypt-passphrase VALUE` flag and there never will be. A passphrase file's
single trailing newline is stripped, because that is what an editor leaves
behind; nothing else is trimmed, since a passphrase may legitimately start or
end with a space. Key, certificate, and passphrase files are each capped at
1 MiB.

**No key material reaches any output.** The paths the caller typed may appear
in messages, because that is how a failure is acted on. The key bytes, the
passphrase, and anything derived from them never appear in a log line, an error
message, a warning, the JSON envelope, or a fixture; a test asserts this over
stdout, stderr, and the envelope on both a successful and a failing run. Key
and passphrase buffers are zeroed when they are dropped.

A certificate is required, and it is checked against the key: its public key
must be the key's public key, or the run fails with `decryption_key_mismatch`.
It is what makes a `RecipientInfo` recognisable, and matching by trial
decryption instead would turn "this is somebody else's document" into "this
key is wrong", which are different answers to different questions.

openSzigno does not read PKCS#12 (`.p12`, `.pfx`). Convert one first:

```sh
openssl pkcs12 -in recipient.p12 -nocerts -out recipient.key.pem
openssl pkcs12 -in recipient.p12 -clcerts -nokeys -out recipient.cert.pem
```

The first command writes a passphrase-protected PKCS#8 key, which
`--decrypt-passphrase-file` reads; add `-nodes` to write it unprotected.

### Where decryption sits, and the limits

The chain is reversed in the order the specification fixes: Base64 first, then
CMS decryption, then ZIP expansion. Every existing bound still applies, and the
plaintext gets its own:

- `max_base64_chars` and `max_decoded_document_bytes` bound the CMS message
  itself, as they bound any payload;
- the plaintext buffer is bounded **before it is allocated** by the ciphertext
  length, which the plaintext can never exceed, and the decrypted length is
  checked against `max_decoded_document_bytes` again once it exists;
- a `zip` transform under the encryption is then expanded under the unchanged
  ZIP rules: one member, a safe name, the expanded-size and compression-ratio
  limits;
- `max_total_decoded_bytes` counts decrypted documents like any other.

### Outcomes

A document that cannot be decrypted is a **skip with a warning**, not a failed
run, whenever the reason is about *this* document rather than about the dossier
or the key: another recipient's document, an algorithm outside the subset, a
refused legacy cipher. A dossier can perfectly well hold documents addressed to
several people, and `extract` should give a caller the ones they can read.

| Situation | Result |
| --- | --- |
| Decrypted | The document is written, with `decrypted: true`. |
| No `--decrypt-key` | `document_skipped_encrypted` warning, exit 0. |
| No `RecipientInfo` names the certificate | `document_skipped_no_matching_recipient` warning, exit 0. |
| Unsupported key transport or content cipher | `document_skipped_unsupported_cipher` warning naming the OID, exit 0. |
| DES-EDE3-CBC without the flag | `document_skipped_legacy_cipher` warning naming the OID, exit 0. |
| Content decryption failed, including a key transport that did not unwrap | `decrypt_failed` error, exit 5. |
| Not well-formed CMS | `invalid_cms` error, exit 5. |
| Key, certificate, or passphrase unusable | `invalid_decryption_key`, `invalid_decryption_certificate`, `decryption_certificate_required`, or `decryption_key_mismatch`, exit 4, before the dossier is decoded. |

`decrypt_failed` carries the fixed message `decryption failed` and nothing
else. Distinguishing a failed RSA unwrap from a bad content-key length from a
bad PKCS#7 padding is exactly the distinction a padding oracle is built out of,
so the tool does not make it, not even in the human output. The RSA half does
not raise it at all; see
[RSA key transport: implicit rejection](#rsa-key-transport-implicit-rejection).

### RSA key transport: implicit rejection

The RSA ciphertext `openszigno-core::decrypt` decrypts, the
`RecipientInfo`'s encrypted content-encryption key, comes from the dossier
being processed, not from the operator. For PKCS#1 v1.5 key transport that
matters: if whether the padding checked out is observable, an attacker able
to submit many crafted dossiers to the same `--decrypt-key` recovers the
content-encryption key without ever holding the RSA private key. That is the
Bleichenbacher/Marvin attack, RUSTSEC-2023-0071.

openSzigno therefore rejects **implicitly**, in `decrypt/keytrans.rs`, the way
OpenSSL 3.2+ (`RSA_PKCS1_IMPLICIT_REJECTION`) and Go's `crypto/rsa` do and RFC
5246 section 7.4.7.1 prescribes:

| Step | What happens |
| --- | --- |
| Private operation | Runs once, blinded with an `OsRng`-seeded factor, through `rsa::hazmat::rsa_decrypt_and_check`, which returns the raw plaintext block instead of unpadding it. |
| Unpadding | Done here, in constant time: the leading `0x00 0x02`, a padding run of at least eight non-zero bytes, the `0x00` separator, and a payload of exactly the announced content cipher's key length all fold into one flag, with no early return and no branch on a plaintext byte. |
| Failure | The block is replaced by a synthetic key of the same length, derived with HMAC-SHA-256 from a per-key secret over the ciphertext and chosen in constant time. |
| After | Content decryption runs unconditionally. A substituted key fails at the content cipher's PKCS#7 padding, as `decrypt_failed`, exactly as a tampered content ciphertext does. |

The content cipher is resolved before the unwrap, because its key length is
what the unpadding checks against; a wrapped key of any other length is
rejected through the same path rather than by a separate length check. The
synthetic key is deterministic per `(private key, ciphertext)` and
unpredictable to whoever supplied the ciphertext, so replaying a dossier gives
an attacker no new information and no substitution can be precomputed.
RSAES-OAEP takes the same shape: it is not the padding this attack is about,
but an OAEP failure is likewise answered with the synthetic key rather than a
distinguishable error.

**What is left** is a timing residual rather than an oracle: `rsa` 0.9's
modular exponentiation is not constant-time, and its big-integer to
byte-string conversion has a length that follows the plaintext's leading zero
bytes. Blinding masks the exponentiation; `rsa` 0.10's crypto-bigint backend
would remove the residual, and has no stable release yet. See the
`RUSTSEC-2023-0071` entry in `deny.toml` for the full write-up, and
[SECURITY.md](../SECURITY.md#rsa-key-transport-decryption-implicit-rejection)
for the operator-facing statement.

One visible consequence: a dossier whose wrapped key is unusable is decrypted
under a synthetic key, so the failure surfaces further down rather than at the
unwrap. Almost always that is the content cipher's PKCS#7 padding, reported as
`decrypt_failed`; roughly once in 256 the padding of garbage is valid by
chance and the answer is `source_size_mismatch` instead, because the decoded
length no longer matches the document's declared source size. `extract` would
write the garbage only if that length matched as well. Decryption asserts
nothing about authenticity either way; see
[Verification boundary](#verification-boundary).

## Verification boundary

`verify` ships the complete M2 subset: canonicalization, reference digests, the
signature value, the e-dossier reference-scope rules, the XAdES signed
`SigningCertificate` binding, RFC 3161 signature timestamps, certificate-path
validation against a caller-supplied trust store and ETSI TS 119 612 trusted
lists, and offline revocation checking. Within that subset it may report a
signature `invalid`, which is a positive cryptographic finding, and it may
report one `valid`.

**What `valid` means, exactly.** Every check this build makes passed at the
stated validation time, against the trust material the caller supplied. It does
**not** mean the dossier is legally valid — that is a legal judgement, and a
permanent non-goal of this tool. It does not mean the signer is who the
certificate says, only that a CA the caller chose to trust said so. It does not
cover anything listed as outside the boundary below. And it is only as good as
the inputs: an empty trust store yields `indeterminate`, not `valid`, and a
trusted list whose own signature was not checked yields `indeterminate` too.

`indeterminate` means "nothing failed", not "this is trustworthy". The human
output states the verdict and the revocation policy it was reached under on
every run.

The rule for the other six commands is unchanged: `inspect`, `list`,
`extract`, `validate-structure`, `create`, and `sign` verify nothing,
`signatures_verified` and
`cryptographic_verification_performed` stay `false`, and the warning
`cryptographic_verification_not_performed` keeps its meaning for them. The
signature inventory `inspect` and `list` report changes nothing about that
boundary: it is the dossier's own claims about its signature material, carries
`"verified": false` in the JSON and an `(unverified)` prefix on every human
line, and a richer inventory is not weaker evidence or stronger evidence but no
evidence at all. See [Signature inventory](#signature-inventory). It is
deliberately *not* emitted by `verify`, which reports what it actually did.

Creating a dossier says nothing about its contents either: `create` signs
nothing, and every run of it warns `created_dossier_unsigned`. **Signing one
says nothing about it either.** `sign` produces a signature with the key it
was given over the elements the format mandates, and checks none of it: not
the key, not the certificate, not the chain, not the token a `--tsa` returned
beyond that it stamps the right imprint. Every successful run warns
`signed_dossier_unverified`. Running `verify` on what `sign` wrote is the only
way to learn whether it holds, and a `valid` verdict over a self-signed test
chain means only that the chain the caller chose to trust verified, which is
not a statement about anybody's identity and not a qualified electronic
signature. A qualified signature needs a key on a qualified device, which by
construction is not a key this process can hold; see
[remote-signing.md](remote-signing.md).
Extracting a document is never proof that it was signed or that the signature
is valid, and neither is decrypting one: `--decrypt-key` shows that a key could
unwrap a payload, which says nothing about who produced it. A rejection is
likewise not proof of forgery: the pinned algorithm policy refuses some genuine
older dossiers, which is the correct trade and must not be misread.

`--online` widens where revocation data may come from and nothing else. It
never relaxes a rule: a fetched CRL or OCSP response is judged by exactly the
offline rules, only URLs published by certificates that reach a configured
trust anchor are contacted, only destinations the policy permits are opened,
and a failed fetch is `revocation_status_unknown`, which blocks. A run that reaches
`valid` with `--online` reached it on evidence that would have supported the
same verdict had the operator downloaded the same files by hand.

`--decrypt-key` likewise widens what `extract` can read and nothing else. It
adds no cryptographic finding to any command, changes no verdict, and cannot
be given to `verify` at all.

Still outside the boundary: `xades:ArchiveTimeStamp` verification, XAdES level
detection, scheme-level trusted-list `Qualifications` extensions, and
signature-policy processing — an explicit policy identifier is reported, and
the policy it names is neither fetched nor enforced.
