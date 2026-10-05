#!/bin/sh
# Builds the Linux archive into target/dist, from anywhere Docker runs:
#
#   deploy/linux/package.sh
#
# The programs are compiled and packed in a container (package.Dockerfile); what
# comes out is peerfectly-<version>-linux-x86_64.tar.gz, and its line in
# target/dist/SHA256SUMS, which a person compares before unpacking.

set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# Under Git Bash on Windows, Docker wants C:/… rather than /c/…, and does not
# get it converted inside `--output`.
if command -v cygpath >/dev/null 2>&1; then
    ROOT=$(cygpath -m "$ROOT")
fi
DIST="$ROOT/target/dist"
mkdir -p "$DIST"

# BuildKit, for the cache mounts and for writing the result out as files.
DOCKER_BUILDKIT=1 docker build \
    --file "$ROOT/deploy/linux/package.Dockerfile" \
    --target dist \
    --output "type=local,dest=$DIST" \
    "$ROOT"

# This archive's line replaces any earlier Linux archive's; the other lines,
# the Windows package's among them, are left as they were.
for digest in "$DIST"/peerfectly-*-linux-x86_64.tar.gz.sha256; do
    archive=$(basename "$digest" .sha256)
    touch "$DIST/SHA256SUMS"
    grep -v -- '-linux-x86_64\.tar\.gz$' "$DIST/SHA256SUMS" > "$DIST/SHA256SUMS.new" || true
    cat "$digest" >> "$DIST/SHA256SUMS.new"
    mv "$DIST/SHA256SUMS.new" "$DIST/SHA256SUMS"
    rm "$digest"
    echo "Built target/dist/$archive"
done
