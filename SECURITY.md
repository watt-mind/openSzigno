# Security policy

## The one thing to know first

openSzigno does not verify anything cryptographic. In the current release it
performs structural validation and bounded extraction only. It does not verify
XMLDSig/XAdES signatures, certificate chains, revocation status, timestamps,
or legal authenticity.

**Extraction is not verification.** A dossier that openSzigno parses, lists,
and extracts without complaint may be entirely forged. Do not use openSzigno
output as evidence that a document is authentic, signed, unmodified, or
legally valid.

Signature and timestamp verification and payload decryption are planned
milestones, described in [docs/roadmap.md](docs/roadmap.md). Until that code
exists, no openSzigno output claims or implies validity: `signatures_present`
and `timestamps_present` are counts, and `signatures_verified` and
`cryptographic_verification_performed` are always `false`.

## Threat model

The assumed attacker supplies the `.es3` input and controls every byte of it,
including its XML structure, declared sizes, transform chain, payload bytes,
and document titles. The operator runs openSzigno on that input, possibly
unattended, possibly as part of an agent pipeline, and extracts into a
directory the attacker cannot write to but may race against.

openSzigno aims to guarantee that a hostile input cannot:

- exhaust memory, stack, or disk beyond the documented limits, including
  through XML nesting, node counts, Base64 length, or ZIP compression ratios;
- cause a panic, an unbounded read, or an unhandled crash instead of a stable
  error code;
- read or fetch anything outside the input file, in particular through DTDs,
  external entities, or entity expansion, all of which are rejected;
- write outside the requested output directory, through a path in a document
  title, a ZIP member path, an absolute path, or a symlink or reparse point in
  the output path;
- overwrite, truncate, or replace an existing file;
- leave a partial extraction behind after a mid-run failure;
- smuggle content into the machine-readable channel, since JSON mode emits
  exactly one object on stdout and all diagnostics go to stderr;
- cause openSzigno to disclose input paths, document titles, or payload
  content in an error message.

The safety mechanisms behind these are documented in
[docs/architecture.md](docs/architecture.md#parser-safety-model) and
[docs/architecture.md](docs/architecture.md#extraction-policy).

## In scope for a report

- Memory exhaustion, stack overflow, unbounded allocation, or a panic reached
  from a crafted `.es3` input.
- Any escape from the documented limits, including ZIP-bomb amplification and
  Base64 or decoded-size bypasses.
- XML external entity, DTD, or entity-expansion processing that is not
  rejected.
- Path traversal, symlink or reparse-point following, file overwrite, or any
  write outside the requested output directory.
- Time-of-check/time-of-use races in output handling on Unix, where the
  descriptor-relative implementation is meant to close them.
- Disclosure of an input path, document title, or payload content in a
  message, warning, error, or diagnostic.
- Any output that states or implies that a signature, timestamp, certificate,
  or dossier is valid.
- Contamination of stdout in `--json` mode, or an exit status that
  contradicts the documented category.

## Out of scope

- The absence of signature, certificate, timestamp, or decryption support.
  That is documented behaviour and tracked as roadmap milestones, not a
  vulnerability.
- A dossier that openSzigno refuses to parse because it uses an unsupported
  namespace, encoding, or transform chain. Report that as a compatibility
  issue; see
  [CONTRIBUTING.md](CONTRIBUTING.md#proposing-a-format-compatibility-change).
- Resource use within the documented limits, for example peak memory that is a
  multiple of a 64 MiB input.
- Directory-swap races on non-Unix platforms, which are a documented residual
  risk in [docs/roadmap.md](docs/roadmap.md#engineering-items). A report that
  demonstrates a *new* class of failure there is still welcome.
- Vulnerabilities in Microsec products, in third-party dossier viewers, or in
  a dependency where the correct venue is that project's own security process.
  Tell us anyway if openSzigno's use of the dependency makes it exploitable.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting for this
repository:

1. Open <https://github.com/watt-mind/openSzigno/security/advisories>.
2. Choose **Report a vulnerability**.

Please do not open a public issue, and do not disclose the problem publicly
until a fix is available.

Include:

- affected version or commit, and platform;
- what happens and what should happen instead;
- a **synthetic** reproducer. Never attach a real dossier, a private path, a
  document title, payload bytes, a certificate subject, or a signature value.
  If the trigger comes from a real file, describe it structurally and, where
  possible, rebuild it as synthetic data.

We aim to acknowledge a report within seven days and to agree a disclosure
timeline with the reporter. Fixes land on `develop`, are merged to `master`,
and are noted in [CHANGELOG.md](CHANGELOG.md) with credit if the reporter
wants it.

## Supported versions

The project is pre-1.0. Only the latest release and the current `develop`
branch receive security fixes.
