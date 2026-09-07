# openSzigno documentation

Start with the [README](../README.md) for installation, a quick start, and the
command reference.

| Document | Contents |
| --- | --- |
| [architecture.md](architecture.md) | Canonical reference: crate shape, format scope, parser safety model, limits, JSON envelope, stable error and warning codes, exit statuses, extraction policy, the `verify` pipeline with its check codes and algorithm policy, and the verification boundary. |
| [research.md](research.md) | What an `.es3` e-dossier is, the primary Microsec and IANA sources, the container and transform model, other implementations reviewed, and the security conclusions that shaped the design. |
| [testing.md](testing.md) | Test layout, how to run tests and coverage, the public fixture policy, and the private opt-in smoke tests. |
| [verify-design.md](verify-design.md) | M2 design proposal for XMLDSig/XAdES verification: Rust ecosystem survey, pipeline stages and stable check codes, JSON result shape, trust and revocation policy, phased delivery. |
| [references.md](references.md) | Index of the primary specifications, standards, RFCs, trust-list and CA material the project relies on, with canonical links and checksums; the files themselves live in the gitignored `refs/` cache. |
| [releasing.md](releasing.md) | How a release is cut: the branch and tag steps, what each release workflow produces, the distribution channels, the required secrets and organisation-side setup, and how to rehearse a release with a prerelease tag. |
| [roadmap.md](roadmap.md) | Ordered milestones (custom namespaces, signature verification, timestamp verification, decryption), engineering items, residual risks, and the private-corpus policy for maintainers. |

Project policies live at the repository root:

| Document | Contents |
| --- | --- |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Branch model, commit conventions, required checks, and fixture and privacy rules. |
| [SECURITY.md](../SECURITY.md) | Threat model, what is in and out of scope, and how to report a vulnerability. |
| [CHANGELOG.md](../CHANGELOG.md) | Release history in Keep a Changelog format. |
