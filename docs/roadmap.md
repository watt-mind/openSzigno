# Roadmap, residual risks, and maintainer policy

This document lists planned work beyond the current extraction-only release,
the risks that remain in the shipped code, and the maintainer rules for the
private test corpus.

Nothing here changes the rule stated in
[architecture.md](architecture.md#verification-boundary): until the code for a
milestone exists, no openSzigno output may claim or imply that a signature,
timestamp, certificate, or dossier is valid.

## Format and verification milestones

The milestones are ordered. Each one is expected to keep the JSON envelope
stable, or to raise `schema_version` if it cannot.

### M1: custom compatible e-dossier namespaces

Support e-dossier profiles that use a compatible namespace other than the
default `https://www.microsec.hu/ds/e-szigno30#`, such as the Hungarian
company-court (e-cégeljárás) dossiers. Scope:

- an explicit allow-list of recognised namespaces, resolved namespace-aware
  at the root element, never by file extension;
- per-namespace structural expectations where they differ from the default
  profile, with the Microsec prose specification as the authority;
- `inspect` continues to report the detected `namespace` verbatim, so a caller
  can tell which profile was applied;
- an unknown namespace stays a `wrong_root` error rather than a best-effort
  parse.

### M2: `verify` for XMLDSig/XAdES signatures

Add a `verify` command that validates signature material. Scope:

- strict same-document ID resolution and duplicate-ID rejection, reusing the
  existing ID space rules;
- reference-scope enforcement against the e-dossier placement rules in the
  primary specification, plus canonicalization;
- a pinned algorithm policy, with weak digests and signature algorithms
  rejected rather than warned about;
- configurable trust store, and an explicit online/offline certificate
  revocation policy with the chosen policy reported in the result;
- certificate-path validation to a configured trust anchor;
- distinct stable codes and a distinct exit-status category for a
  cryptographic failure, so a caller can tell it apart from a structural one.

Until this ships, `signatures_present` is a count and nothing more.

### M3: timestamp verification

Validate `es:TimeStamp` material once M2 provides the trust and algorithm
machinery. Scope: timestamp token parsing, imprint comparison against the
signed data, timestamp authority certificate validation, and a reported
verification time. `timestamps_present` remains presence-only until then.

### M4: encrypted payload decryption

Extract documents whose transform chain contains `encrypt`, using key material
supplied by the user. Scope:

- key and passphrase input through a file or an environment variable, never a
  command-line argument that would land in the process table or shell history;
- key material excluded from every log line, error message, and JSON field;
- the same bounded decoding limits applied to decrypted output as to any other
  payload;
- decryption reported as a distinct capability flag, and never conflated with
  signature verification.

Until this ships, an encrypted document is reported with
`encrypted_document_unsupported` and skipped by `extract` with
`document_skipped_encrypted`.

## Field observations from the private corpus

Aggregate findings from the maintainers' private corpus (see the policy
below), recorded here because they shape priorities. No individual dossier is
identified.

- Roughly four in five dossiers use the default Microsec namespace; the rest
  are company-court (e-cégeljárás) dossiers in four namespace generations
  (2007, 2009, 2012, 2014). Those carry many more documents per dossier
  (up to a dozen or more), all `base64` without `zip`, and some embed a
  nested dossier declared as `application/nldossier2` whose payload is itself
  a default-namespace `Dossier`. Milestone M1 must handle nested dossiers.
- Payloads are overwhelmingly PDF and small HTML notices, with a few XML
  documents (including a Microsec `Acknowledge` receipt). About half of the
  PDFs have no text layer and are image-only scans, so text extraction from
  payloads is out of scope for this tool and belongs to the calling agent.
- Declared MIME types are not reliable: `application/octet-stream` payloads
  turned out to be PDF and HTML, and a `text/xml` payload was HTML. A
  content-sniffing hint alongside the declared type would help agents choose
  a reader without opening the file blind.
- Every parsed dossier carried signature material and a minority carried
  timestamps, which is why `verify` is the next milestone after M1.
- Inputs with the `.es3` suffix that are not XML at all occur in practice
  (tiny Base64-like text fragments); the `invalid_xml` rejection is correct.

## Engineering items

These are not format milestones; they can land in any order.

| Item | Why it matters |
| --- | --- |
| Windows extraction race | On Unix the output path is walked descriptor-relative with `O_NOFOLLOW`, which closes the directory-swap race. On Windows and other non-Unix targets, files are created by path with no-clobber semantics and reparse-point rejection, so a directory swapped between the check and the create remains a residual risk. Closing it needs platform-specific handle-relative creation. |
| Configurable limits | Limits are compile-time defaults today. They should be settable per invocation, with the effective values still reported in `inspect` output and a documented ceiling so that a flag cannot disable a bound entirely. |
| Streaming extraction | Every document is decoded in memory before any file is written, which is what makes the all-or-nothing extraction guarantee cheap, but it makes peak memory a multiple of the input size. Streaming decode to a temporary file inside the output directory, then atomically linking on success, would lower peak memory while keeping the guarantee. |
| Broader interoperability corpus | Vendor differential testing against consented real dossiers covering UTF-8 and ISO-8859-2, document-level and dossier-level signatures, timestamps, multiple payloads, ZIP, and encryption markers. |

## Residual risks in the current release

- **Memory.** Peak memory is roughly a small multiple of the input size. The
  64 MiB input cap and the 256 MiB aggregate decode cap bound it, but a caller
  running many instances in parallel must budget for that.
- **Non-Unix filesystem races.** See the Windows item above.
- **Parser surface.** Safety rests on the pre-parse scan plus `roxmltree` with
  DTDs disabled. The pre-parse scan is deliberately conservative and only has
  to be correct for well-formed input; anything it miscounts on malformed
  input is rejected by the tree parser afterwards. Changes to either side need
  matching regression tests.
- **Compatibility gaps.** Dossiers in unsupported namespaces or with
  unsupported transform chains are rejected or skipped. A rejection is not
  evidence that a dossier is malformed; it may simply be out of the currently
  supported profile.
- **No cryptographic assurance at all.** A dossier that parses cleanly may be
  entirely forged. This is the single most important thing for a downstream
  caller to internalise.

## Private-corpus policy for maintainers

Maintainers may hold real-world `.es3` dossiers locally for compatibility
testing. They are private integration inputs, never fixtures.

- `samples/` is gitignored except for its `.gitkeep`. Never commit, stage, or
  modify anything in it, and never derive a public fixture from it.
- Never print, enumerate, hash, or otherwise disclose private paths or
  filenames, dossier or document titles and metadata, payload contents or
  hashes, or certificate subjects, signer data, and signature values. This
  applies to failure paths, patches, issue reports, CI logs, and chat
  transcripts alike.
- Avoid commands that echo private filenames, such as directory listings over
  the corpus or shell loops that print paths. Use the opt-in tests, which take
  their input through an environment variable and report aggregate results
  only. See [testing.md](testing.md#private-opt-in-smoke-tests).
- Report compatibility findings as aggregate counts and stable error-code
  buckets. A useful finding reads "N inputs bucketed to `wrong_root`", never
  "file X failed".
- Never weaken a security check merely to raise the number of dossiers that
  parse. If a rejection turns out to be an in-scope compatibility bug, fix the
  format handling and add a synthetic fixture that reproduces it.
- Before accepting any real dossier into the public repository, its
  provenance, privacy status, and redistribution permission must be documented
  and approved. Keep provenance and expected behaviour in a private test-corpus
  manifest, not in the repository.
