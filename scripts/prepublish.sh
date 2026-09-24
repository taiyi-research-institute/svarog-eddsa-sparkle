#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

package_flags=()
case "$#:${1-}" in
    0:) ;;
    1:--allow-dirty) package_flags+=(--allow-dirty) ;;
    *) printf '%s\n' 'Usage: scripts/prepublish.sh [--allow-dirty]' >&2; exit 2 ;;
esac

cargo fmt --check
cargo test --all-features --locked -- --test-threads=4
cargo clippy --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps --locked
cargo package --locked "${package_flags[@]}"
cargo publish --dry-run --locked "${package_flags[@]}"
