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
