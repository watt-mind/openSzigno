## Summary

<!-- What changes and why. Link the issue if there is one. -->

## Checklist

- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` pass locally
- [ ] New behaviour has tests; fixtures are synthetic, unsigned, and listed in `tests/fixtures/README.md`
- [ ] Stable JSON codes, exit statuses, and `docs/architecture.md` are updated together
- [ ] No real dossier, path, title, hash, or signer data appears in code, tests, fixtures, or this description
- [ ] `CHANGELOG.md` has an entry under Unreleased
