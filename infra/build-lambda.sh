#!/usr/bin/env bash
# Build the Lambda deployment package.
#
# arm64: Graviton is cheaper per millisecond, and this workload is CPU-bound on
# signature verification rather than blocked on I/O.
set -euo pipefail

cd "$(dirname "$0")/.."

command -v cargo-lambda >/dev/null || {
  echo "cargo-lambda is not installed: pip install cargo-lambda" >&2
  exit 1
}

cargo lambda build --release --arm64 -p registry-lambda

OUT="target/lambda/registry.zip"

# Newest first, not whatever the filesystem walk returned first: a stale
# bootstrap from an earlier build for another target sits in the same tree.
BIN="$(find target/lambda -name bootstrap -type f -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)"
[ -n "$BIN" ] || { echo "bootstrap binary not found" >&2; exit 1; }

# Checked before the zip is written. Announcing success and then failing the
# check leaves a deployable wrong-architecture package on disk, and
# `terraform apply` reads that file independently of this script's exit code.
file "$BIN" | grep -q aarch64 || {
  echo "the binary at $BIN is not aarch64; refusing to package it" >&2
  exit 1
}

rm -f "$OUT"
(cd "$(dirname "$BIN")" && zip -q -j "$OLDPWD/$OUT" bootstrap)

echo "$OUT  $(du -h "$OUT" | cut -f1)"
