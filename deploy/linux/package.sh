#!/bin/sh
# Builds the Linux archive into target/dist, from anywhere Docker runs:
#
#   deploy/linux/package.sh
#
# The programs are compiled and packed in a container (package.Dockerfile), for
# this machine's architecture; what comes out is
# peerfectly-<version>-linux-<x86_64|aarch64>.tar.gz, and its line in
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

# This archive's line replaces any earlier archive's for the same architecture;
# the other lines, the other architecture's and the Windows package's among
# them, are left as they were.
for digest in "$DIST"/peerfectly-*-linux-*.tar.gz.sha256; do
    [ -f "$digest" ] || continue
    archive=$(basename "$digest" .sha256)
    arch=${archive##*-linux-}
    arch=${arch%.tar.gz}
    touch "$DIST/SHA256SUMS"
    grep -v -- "-linux-$arch\\.tar\\.gz\$" "$DIST/SHA256SUMS" > "$DIST/SHA256SUMS.new" || true
    cat "$digest" >> "$DIST/SHA256SUMS.new"
    mv "$DIST/SHA256SUMS.new" "$DIST/SHA256SUMS"
    rm "$digest"
    echo "Built target/dist/$archive"
done
