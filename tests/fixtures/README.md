# Synthetic unsigned fixtures

Every file in this directory was created for openSzigno testing. The fixtures
contain no real signatures or personal/company data and are dedicated under
[CC0-1.0](LICENSE).

They test structural parsing and extraction only. They are not authentic or
legally valid e-dossiers and must not be used as signature-verification
evidence.

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
| `compatible-namespace.es3` | A 2014 e-cégeljárás-namespace dossier with one `base64` text document. Parses with two conformance warnings: `dangling_objref` (a `SignatureProfile` whose OBJREF resolves to nothing) and `document_without_profile` (an empty `Document` holding only an empty `ds:Object`). |
