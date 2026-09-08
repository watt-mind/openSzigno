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

Permanent non-goals for this tool:

- creating, editing, signing, timestamping, or encrypting dossiers;
- declaring a dossier legally valid, which is a legal judgement rather than a
  cryptographic result;
- silently accepting arbitrary XML that merely has an `.es3` suffix.

## Crate shape

```text
crates/
  openszigno-core/    # XML model, bounded decoding, transforms, stable codes
  openszigno-verify/  # canonicalization, XMLDSig, certificate paths
  openszigno-cli/     # clap commands, human output, JSON protocol, exit codes
```

`openszigno-core` does not write files or print output. The CLI owns all
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
  input.rs            # the bounded reader for a file or stdin, InputInfo, load
  response.rs         # the JSON envelope, CliError, and its exit statuses
  render/             # writing the envelope (json.rs) and the summary (human.rs)
  commands/           # one module per command: inspect, list, validate,
                      #   extract, verify
  extract/            # select.rs (--document), plan.rs (decode, names, nesting),
                      #   names.rs (filename safety), write.rs (writing and
                      #   rollback), output_dir.rs (race-resistant output)
  trust.rs            # --trust-store, --trust-list, and --lotl loading
  revocation_store.rs # --revocation-store loading
  online/             # --online fetching, the only code that opens a socket
    mod.rs            #   the trust gate, the gap search, the transport, the cache
    destination.rs    #   which URLs and addresses may be contacted at all
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
   inputs fail with `input_too_large` before parsing.
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
under `data.limits`. They are not yet configurable on the command line; see
[roadmap.md](roadmap.md).

| Limit | Default | Enforced by | Purpose |
| --- | --- | --- | --- |
| `max_input_bytes` | 67108864 (64 MiB) | core and CLI | Raw dossier file size. |
| `max_documents` | 256 | core | `es:Document` elements per dossier. |
| `max_base64_chars` | 100663296 (96 MiB) | core | Base64 characters in one payload after whitespace removal. |
| `max_decoded_document_bytes` | 67108864 (64 MiB) | core | Decoded size of one document. |
| `max_total_decoded_bytes` | 268435456 (256 MiB) | CLI | Aggregate decoded size of one extraction, across the whole embedded-dossier tree. |
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
| `verify FILE` | Verify every `ds:Signature`: canonicalization, reference digests, the signature value, the e-dossier reference-scope rules, and the certificate path. Cannot report a signature as `valid` in this release. | No |

In every command `FILE` is either a path to a regular file or `-`, which
reads the dossier from standard input; see [Reading from stdin](#reading-from-stdin).

`verify` additionally accepts `--trust-store <DIR>` and `--at <RFC3339>`; see
[The `verify` command](#the-verify-command).

All commands accept `--json` and `--allow-namespace <URI>` (repeatable).
`extract` additionally accepts:

| Flag | Meaning |
| --- | --- |
| `--no-recursive` | Write an embedded dossier as a plain payload file instead of expanding it. |
| `--max-depth <N>` | Nesting levels of embedded dossiers to expand, default 3; values above the hard cap of 8 are clamped to 8. |
| `--document <SELECTOR>` | Extract only the named documents. Repeatable. See [Selecting documents](#selecting-documents). |
| `--stdout` | Write one document's raw payload bytes to stdout. See [The payload stdout mode](#the-payload-stdout-mode). |
| `--decrypt-key <FILE>` | RSA private key, PKCS#8 DER or PEM, plain or passphrase-protected, used to decrypt `encrypt` documents. See [Decryption](#decryption). |
| `--decrypt-cert <FILE>` | The certificate belonging to `--decrypt-key`, PEM or DER. Optional when the key file is PEM and carries the certificate too. Requires `--decrypt-key`. |
| `--decrypt-passphrase-file <FILE>` | Read the passphrase of an encrypted key from this file. Requires `--decrypt-key`. |
| `--allow-legacy-ciphers` | Also decrypt DES-EDE3-CBC content. Requires `--decrypt-key`. |

In JSON mode, stdout contains exactly one JSON object and diagnostics go to
stderr. Document ordering is the source XML order. No command writes XML
payload bytes to stdout except `extract --stdout`, which writes the selected
document's payload and nothing else.

### Reading from stdin

`FILE` may be `-`, which reads the dossier from standard input instead of from
a path. It works for every command, through the same bounded reader, and the
envelope's `input.format` and `input.bytes` are reported exactly as they are
for a file.

- At most `max_input_bytes + 1` bytes are read. Arriving at that many is
  `input_too_large` (exit 4), the same code a file over the cap produces, and
  `input.bytes` is `null` because the true size of a stream that was not read
  to its end is unknown.
- The cap is enforced on the bytes actually read. No filesystem metadata is
  consulted, because a pipe has none and a file's metadata can change between
  the check and the read.
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

## JSON envelope

The envelope fields are always present:

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | number | Currently `1`. |
| `ok` | boolean | `false` on any failure. |
| `command` | string | `inspect`, `list`, `extract`, `validate-structure`, `verify`, or `usage`. |
| `input` | object | `format` is `"microsec-es3"` or `null`; `bytes` is the input size or `null`. |
| `data` | object or null | Command-specific; `null` on failure. |
| `warnings` | array | Objects with stable `code` and human `message`. |
| `errors` | array | Objects with stable `code` and human `message`. |

Messages never contain input paths, document titles, or payload content. On
failure `data` is `null`, `warnings` is empty, and `input.format` is `null`
when the input could not be parsed as a dossier.

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
| `verify` | `verdict`, `verification_time`, `policy`, `limits`, `counts`, `checks`, `signatures`. See [The `verify` command](#the-verify-command). |

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
| `too_many_documents` | core | 4 | More than `max_documents` documents. |
| `decoded_too_large` | core | 4 or 5 | A declared or decoded payload exceeds a size limit (4 when detected during parsing, 5 during extraction). |
| `invalid_base64` | core | 5 | Payload is not canonical Base64. |
| `source_size_mismatch` | core | 5 | Decoded length differs from the declared `SourceSize`. |
| `invalid_zip` | core | 5 | ZIP payload is malformed or cannot be expanded. |
| `zip_member_limit` | core | 5 | The archive does not contain exactly one member. |
| `zip_size_limit` | core | 5 | The ZIP member exceeds the expanded-size limit. |
| `zip_ratio_limit` | core | 5 | The ZIP member exceeds the compression-ratio limit. |
| `unsafe_zip_member` | core | 5 | The member is a directory, a symlink, or has a non-basename path. |
| `unsupported_zip_member` | core | 5 | The member uses encryption or an unsupported compression method. |
| `invalid_decryption_key` | core | 4 | `--decrypt-key` is not an RSA private key in PKCS#8 DER or PEM form, or its passphrase is missing or wrong. The two are deliberately not told apart. |
| `invalid_decryption_certificate` | core | 4 | `--decrypt-cert`, or the certificate inside the key file, is not a readable X.509 certificate with an RSA public key. |
| `decryption_certificate_required` | core | 4 | `--decrypt-key` was given with no certificate, and the key file carries none. Without one the recipient this key belongs to cannot be recognised. |
| `decryption_key_mismatch` | core | 4 | The certificate's public key is not the given key's public key. |
| `invalid_cms` | core | 5 | An encrypted payload is not a well-formed CMS `EnvelopedData` `ContentInfo`, carries no encrypted content, or has a malformed initialisation vector or block length. |
| `decrypt_failed` | core | 5 | Decryption failed. The message is exactly `decryption failed` and never says which step failed. |
| `unsafe_output_name` | CLI | 5 | A document title or declared extension cannot be used as a filename, or the derived `<file>.d` directory name would be too long. |
| `output_name_collision` | CLI | 5 | Residual: two outputs still map to the same name in one directory after deduplication. |
| `output_exists` | CLI | 5 | A destination file already exists or cannot be created safely. |
| `document_not_found` | CLI | 4 | A `--document` selector matches no document, is not a decimal index after `#`, or names a document inside an embedded dossier. |
| `document_ambiguous` | CLI | 4 | A `--document` `object_ref` selector matches more than one document. Unreachable through a parsed dossier, whose XML IDs are unique. |
| `stdout_requires_single_document` | CLI | 4 | `--stdout` did not resolve to exactly one document, or the one it resolved to embeds a dossier while recursion is on. |
| `document_not_extractable` | CLI | 5 | The document `--stdout` selected is encrypted or uses an unsupported transform chain. |
| `trust_store_invalid` | CLI | 3 | `--trust-store` does not name a readable directory, holds a file that is not PEM or DER certificate data, or holds no trust anchor. A partially loaded store would silently change what "trusted" means, so the run fails instead. |
| `unsafe_output_directory` | CLI | 5 | The output path contains a symlink or reparse point, or is not a real directory. |
| `total_size_limit` | CLI | 5 | Aggregate decoded size exceeds `max_total_decoded_bytes`. |

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

1. **Structure and policy.** `ds:SignedInfo` and `ds:SignatureValue` are
   present; the signature sits at `//es:Document/ds:Signature`,
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

### Module map

`openszigno-verify` is organised as the pipeline above, one module per stage.
The split is internal; the crate's public API is unchanged.

| Module | What it owns |
| --- | --- |
| `lib.rs` | The `verify` entry point: the run's `Context`, the per-signature loop through stages A to F, and the dossier-level assembly (container timestamps, coverage, counts, verdict). |
| `dsig` | The shared `Context` and the small XML helpers every stage is built from, plus re-exports of the items that used to live here. |
| `references` | One `ds:Reference`: parsing, same-document resolution on the validated ID space, the transform allowlist and its application, and digest recomputation. |
| `scope` | Placement classification (`Placement`, `placement_of`), the mandated e-dossier reference sets, and `reference_scope_check`. |
| `countersign` | Countersignature detection, the binding check, and the reported role, parent and `countersigns` set. |
| `signature` | The per-signature driver (stages A and B): `signed_info.rs` parses `ds:SignedInfo` and applies the signature-level algorithm policy, `collect.rs` gathers the timestamp tokens and the octets each one covers, and `mod.rs` keeps signer selection and `ds:SignatureValue` verification. |
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

A reference covers a required element when the element is the resolved node or
a descendant of it, so a `URI=""` reference covers everything, and a reference
to a `ds:Object` covers what it wraps. Two rules follow from what real
dossiers actually contain:

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

An element counts as covered when it is a resolved node or a descendant of
one, which is exactly the rule the scope check applies. A document-level
signature covers only the document it is placed in.

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
subdirectories and symlinks are skipped rather than followed. **Every entry is
parsed as an X.509 certificate at load time**, so a store that loads is one
whose every byte was understood: one malformed entry among good ones fails the
whole store. A file above 4 MiB, a directory holding more than 1024 entries, an
entry that is not a valid certificate, and an empty store are all
`trust_store_invalid` (exit 3), and the message names the entry's ordinal, never
the file, because the path may be private. No trust anchors are compiled into
the binary.

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

Only `granted` and `recognisedatnationallevel` count as granted. The pre-eIDAS
statuses (`undersupervision`, `accredited`) and every terminal one
(`withdrawn`, `supervisionceased`, the `deprecated*` family) do not: this build
refuses to guess which historical status was equivalent to which.

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

Offline by default and offline only. Data is consulted in this order, and the
first source that yields a definite answer for a certificate wins:

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
one entirely offline verification pass first, purely to learn it, and
`VerifyReport::validated_path_certificates` returns the certificates of every
chain whose own path check passed (`cert_path_ok`, `timestamp_tsa_path_ok`).
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
put to the *same* offline code path the verdict will use; only a certificate
that comes back without a definite answer is fetched for. OCSP is tried before
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
| Address | loopback (`127/8`, `::1`), RFC 1918 private (`10/8`, `172.16/12`, `192.168/16`), link-local (`169.254/16`, `fe80::/10`), unique-local (`fc00::/7`), unspecified (`0.0.0.0/8`, `::`), broadcast (`255.255.255.255`) and multicast (`224/4`, `ff00::/8`) are all refused, as are the cloud metadata addresses `169.254.169.254` and `fd00:ec2::254` and the name `localhost` (and `*.localhost`) | Otherwise a dossier could point the verifier at `http://169.254.169.254/` — instance metadata, credentials included — or at a service on the operator's own subnet, turning a signature check into an SSRF primitive. An IPv4-mapped IPv6 address is judged as the IPv4 address it carries, so it is not a way round any of these. The two metadata addresses are named in their own refusal, because that is the one an operator wants to be told about explicitly. |
| Resolved address | re-checked against the same ranges before connecting | A public name that resolves to `127.0.0.1` is refused on the address, not on the name, so DNS rebinding does not walk past the rule. `ureq` resolves again when it connects, so this is a mitigation and not a proof. |
| Every hop | the URL the certificate published and **each redirect target** go through the whole policy | A redirect already may not leave the host, but "the same name" and "the same address" are different statements. |

`--online-allow-private` waives the address rules — and only those — for an
internal CA that really does publish on a private network. This project's own
test suite passes it, because it serves a synthetic PKI from `127.0.0.1`.

**The transport policy.**

| Rule | Value | Why |
| --- | --- | --- |
| Schemes | `http` and `https`, exactly as published | Neither is rewritten. Upgrading `http` to `https` is a guess about a host's configuration. Confidentiality is not the point: these are public documents and every one is signature-checked before it is believed. |
| Connect timeout | 5 s | |
| Total timeout | 20 s per fetch | A fetch that exceeds it is a named failure, never a hang. |
| Size cap | `MAX_REVOCATION_ITEM_BYTES` (16 MiB) for a CRL, 64 KiB for an OCSP response | Enforced by the reader, so a server that lies about `Content-Length` cannot make the run allocate more. The CRL cap is the *verifier's own* limit, re-exported: a download cap larger than what the tier walk will parse meant a CRL could arrive, be stored, and then answer nothing. |
| Redirects | at most 3, **never to another host** | The authority for a URL is the certificate, and the certificate named one host. The port is part of the host. |
| Proxy | none, unless `--online-proxy URL` | `HTTP_PROXY` and its relatives are ignored. A verifier that silently routed its revocation traffic through whatever the shell happened to set would hand an attacker who controls that variable a way to feed it chosen bytes. |
| Requests | `GET` for a CRL; `POST` of an RFC 6960 `OCSPRequest` as `application/ocsp-request` for OCSP | The `certID` uses **SHA-256**, which is inside the pinned allowlist. No nonce is sent: a nonce defends a live request against replay, and the verifier deliberately ignores nonces because it must also read archived responses. |
| Volume | at most 32 certificates per run, at most 4 URLs per certificate | Opening one dossier cannot generate unbounded traffic. |

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
all), or `cache_collision` (the artefact was fetched, but `--online-cache`
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
| `sig_structure` | `passed` | `ds:SignedInfo`, `ds:SignatureValue`, the methods, and at least one reference are present and within limits. |
| `sig_structure_invalid` | `failed` | One of those is missing, malformed, or over a limit. |
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
| `xades_signing_certificate_absent` | `unknown` | The signature carries no such property, so nothing signed says which certificate signed it. |
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
| `online_fetch_failed` | `info` | Under `--online`, one fetch did not produce a usable artefact. The message names the URL and the failure class: `timeout`, `http status <code>`, `too large` with the limit, `redirect`, `invalid`, `transport`, `destination_refused` with the rule that refused the destination before any socket was opened, or `cache_collision` when `--online-cache` already held a different file under an artefact's name and nothing was overwritten. Informational: whether the missing data mattered is answered by the chain that needed it, through `revocation_status_unknown`, which blocks. |
| `ocsp_responder_trusted` | `info` | An OCSP response was accepted under the RFC 6960 section 2.2 trusted-responder model: the responder is not the issuing CA and that CA did not delegate to it, but its certificate carries `id-kp-OCSPSigning` and chains to a configured anchor. Reported because this rests on the caller's trust store rather than on the issuing CA's word. |
| `trust_list_loaded` | `info` | A `--trust-list` file was read; the message says how many anchors it contributed. |
| `trust_list_unverified` | `unknown` | A trusted list was used without `--trust-list-signer`, so its own signature was not checked. Blocking. |
| `trust_list_signature_ok` | `passed` | The list's enveloped XMLDSig signature verified against the supplied signer certificate and covers the whole document. |
| `trust_list_signature_invalid` | `failed` | It did not verify, does not cover the whole list, uses an algorithm or transform outside the allowlist, or is absent while a signer was demanded. |
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
  and its `dossier_path` only. Comparison stays case-insensitive, and a name
  that still collides after renaming is the residual error
  `output_name_collision`, which aborts the run with nothing written.
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
milestone. **Decryption is not verification and never becomes it**: reading a
document proves that a key could unwrap it, not that anybody signed it, and
not that the signer is who a certificate says. Every statement in
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
| Key unwrap or padding failed | `decrypt_failed` error, exit 5. |
| Not well-formed CMS | `invalid_cms` error, exit 5. |
| Key, certificate, or passphrase unusable | `invalid_decryption_key`, `invalid_decryption_certificate`, `decryption_certificate_required`, or `decryption_key_mismatch`, exit 4, before the dossier is decoded. |

`decrypt_failed` carries the fixed message `decryption failed` and nothing
else. Distinguishing a failed RSA unwrap from a bad content-key length from a
bad PKCS#7 padding is exactly the distinction a padding oracle is built out of,
so the tool does not make it — not even in the human output.

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

The rule for the other four commands is unchanged: `inspect`, `list`,
`extract`, and `validate-structure` verify nothing, `signatures_verified` and
`cryptographic_verification_performed` stay `false`, and the warning
`cryptographic_verification_not_performed` keeps its meaning for them. The
signature inventory `inspect` and `list` report changes nothing about that
boundary: it is the dossier's own claims about its signature material, carries
`"verified": false` in the JSON and an `(unverified)` prefix on every human
line, and a richer inventory is not weaker evidence or stronger evidence but no
evidence at all. See [Signature inventory](#signature-inventory). It is
deliberately *not* emitted by `verify`, which reports what it actually did.

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
