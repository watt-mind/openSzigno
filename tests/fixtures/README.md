# Synthetic fixtures

Every file in this directory was created for openSzigno testing. The fixtures
contain no real signatures or personal/company data and are dedicated under
[CC0-1.0](LICENSE).

All of them are unsigned except `xmldsig/openssl-rsa-sha256.es3`, which
carries one signature made by a synthetic test PKI whose private keys are not
committed. They are not authentic or legally valid e-dossiers, and none of
them may be used as evidence that any signature is genuine.

| File | Expected behavior |
| --- | --- |
| `plain-base64.es3` | Extracts `hello.txt`. |
| `zip-base64.es3` | Reverses `zip -> base64` and extracts `zipped.txt`. |
| `duplicate-id.es3` | Rejected as `duplicate_id`. |
| `unresolved-objref.es3` | Rejected as `unresolved_objref`. |
| `invalid-base64.es3` | Parses structurally; extraction rejects `invalid_base64`. |
| `traversal-title.es3` | Parses structurally; extraction rejects `unsafe_output_name`. |
| `encrypted.es3` | Parses and reports the document as encrypted/unsupported. |
| `doctype.es3` | Rejected as `unsafe_xml`. |
| `xmldsig/` | An independent XMLDSig vector: a signed dossier whose digests and signature value were produced by OpenSSL and Python over hand-written canonical octets, plus its certificates and generator. See [xmldsig/README.md](xmldsig/README.md). |
| `nested-dossier.es3` | One `application/nldossier2` document (`court.dosszie`) whose Base64 payload is a complete default-namespace dossier. `extract` writes `court.dosszie` and `court.dosszie.d/inner.txt`; `--no-recursive` writes only the first. |
| `two-documents.es3` | Two `base64` text documents, `first.txt` (`DocumentObjectA`) and `second.txt` (`DocumentObjectB`), for `--document` selection and for the `--stdout` refusal when more than one document is in scope. |
| `created.es3` | What `openszigno create` writes from the two inputs under `create/`, at `--created 2026-01-01T00:00:00Z` and the title `Synthetic created dossier`. `crates/openszigno-cli/tests/create.rs` asserts `create` reproduces it byte for byte, and the golden `create` case rebuilds it, so it is also the reader's fixture for a dossier this project authored. |
| `create/hello.txt`, `create/note.txt` | The two synthetic inputs `created.es3` is built from. They are not dossiers and the fixture matrix does not run commands over them. |
| `compatible-namespace.es3` | A 2014 e-cégeljárás-namespace dossier with one `base64` text document. Parses with two conformance warnings: `dangling_objref` (a `SignatureProfile` whose OBJREF resolves to nothing) and `document_without_profile` (an empty `Document` holding only an empty `ds:Object`). |
