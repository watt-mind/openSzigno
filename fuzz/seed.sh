#!/usr/bin/env bash
# Regenerate fuzz/corpus/<target>/* deterministically.
#
# Run from anywhere; paths are resolved relative to this script. Safe to
# re-run: every seed file is (re)written under a fixed name, nothing is
# deleted first, and the generator only reads tests/fixtures and its own
# hand-built synthetic bytes (see fuzz/seeds/src/main.rs), never samples/ or
# a private corpus.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cargo run --manifest-path "$script_dir/seeds/Cargo.toml" --quiet
