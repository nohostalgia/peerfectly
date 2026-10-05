# Builds the Linux archive: the two programs, the unit and the install script,
# with their digests. Run by package.sh beside this file, from the repository
# root; the archive is the only thing that comes out.
#
# Everything happens in Linux, including the packing: a tar made on a Windows
# checkout records whatever modes that file system pretends to have, and an
# install script that is not executable is a confusing first minute.

# The testbed's base, so that what is shipped is what is tested. It also fixes
# the oldest C library the programs run on, which the install script is told.
FROM rust:1.95-bookworm AS build
# `libtss2-dev` for `tss-esapi`, which links the system's TSS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libtss2-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# The same cache mounts as the testbed's, so a package after a testbed run, or
# the other way round, does not compile the tree twice.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release -p programs \
    && mkdir /out \
    && cp target/release/peerfectlyd target/release/peerfectly /out/

FROM build AS pack
RUN set -eu; \
    version=$(awk '/^\[workspace.package\]/ { inside = 1; next } /^\[/ { inside = 0 } \
                   inside && $1 == "version" { gsub(/"/, "", $3); print $3; exit }' Cargo.toml); \
    floor=$(objdump -T /out/peerfectlyd /out/peerfectly | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' \
            | sort -uV | tail -n 1); \
    name="peerfectly-$version-linux-x86_64"; \
    mkdir -p "/pack/$name" /dist; \
    install -m 0755 /out/peerfectlyd /out/peerfectly "/pack/$name/"; \
    install -m 0644 deploy/linux/peerfectlyd.service "/pack/$name/"; \
    sed -e "s/@VERSION@/$version/" -e "s/@GLIBC_FLOOR@/$floor/" deploy/linux/install.sh \
        > "/pack/$name/install.sh"; \
    chmod 0755 "/pack/$name/install.sh"; \
    (cd "/pack/$name" && sha256sum peerfectlyd peerfectly peerfectlyd.service install.sh > SHA256SUMS); \
    tar --sort=name --owner=0 --group=0 --numeric-owner -C /pack -czf "/dist/$name.tar.gz" "$name"; \
    (cd /dist && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256"); \
    echo "$name: glibc $floor or later"

FROM scratch AS dist
COPY --from=pack /dist/ /
