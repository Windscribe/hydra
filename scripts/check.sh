#!/bin/sh
# Local equivalent of CI. Run inside rust:1-slim-bookworm.
set -eu
rustup component add rustfmt clippy >/dev/null 2>&1
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release
