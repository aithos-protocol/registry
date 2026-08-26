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
BIN="$(find target/lambda -name bootstrap -type f | head -1)"
[ -n "$BIN" ] || { echo "bootstrap binary not found" >&2; exit 1; }

rm -f "$OUT"
(cd "$(dirname "$BIN")" && zip -q -j "$OLDPWD/$OUT" bootstrap)

echo "$OUT  $(du -h "$OUT" | cut -f1)"
file "$BIN" | grep -q aarch64 || { echo "WARNING: the binary is not aarch64" >&2; exit 1; }
