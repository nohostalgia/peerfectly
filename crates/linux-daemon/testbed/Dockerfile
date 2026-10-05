# The Linux daemon's testbed: nodes that are real Linux daemons, each with its
# own packet device and, where asked, its own software TPM. Built from the
# repository root by compose.yaml beside this file.
#
# Three stages: `build` compiles the programs from the workspace's lockfile,
# `node` is what a testbed machine runs, and `tests` runs the tests that need a
# kernel, a TPM and root — the `#[ignore]`d ones.

FROM rust:1.95-bookworm AS build
# `libtss2-dev` for `tss-esapi`, which links the system's TSS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libtss2-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# The cache mounts keep the registry and the build between runs, so a rebuild
# after an edit costs minutes rather than the whole tree.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release -p programs \
    && cp target/release/peerfectlyd target/release/peerfectly /usr/local/bin/

# What the programs need at run time, and what a person needs to look.
FROM debian:bookworm-slim AS node
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libtss2-esys-3.0.2-0 libtss2-tctildr0 libtss2-mu0 libtss2-sys1 \
        libtss2-tcti-device0 libtss2-tcti-swtpm0 \
        swtpm swtpm-tools tpm2-tools \
        nftables iproute2 iputils-ping dnsutils netcat-openbsd sudo ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Two people: `alice` may use sudo, `bob` may not. A password prompt would
# stand in the way of every step, so `alice` has none — this is a testbed.
# `TPM2TOOLS_TCTI` survives sudo so that a node's own software TPM is the one
# the command line reaches; on a real machine it is unset, and the TPM is
# `/dev/tpmrm0`.
RUN useradd --create-home --uid 1000 --groups sudo --shell /bin/bash alice \
    && useradd --create-home --uid 1001 --shell /bin/bash bob \
    && printf 'alice ALL=(ALL) NOPASSWD: ALL\nDefaults env_keep += "TPM2TOOLS_TCTI"\n' > /etc/sudoers.d/testbed \
    && chmod 0440 /etc/sudoers.d/testbed
COPY --from=build /usr/local/bin/peerfectlyd /usr/local/bin/peerfectly /usr/local/bin/
COPY --chmod=0755 crates/linux-daemon/testbed/entrypoint.sh /usr/local/bin/entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint"]

# The ignored tests: the toolchain, the source, and what the tests drive —
# `alice` among them, a person who may use sudo, to be looked through.
FROM build AS tests
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        swtpm swtpm-tools tpm2-tools libtss2-tcti-swtpm0 \
        nftables iproute2 iputils-ping netcat-openbsd util-linux sudo \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --groups sudo alice \
    && printf 'alice ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/testbed \
    && chmod 0440 /etc/sudoers.d/testbed
CMD ["cargo", "test", "--locked", "-p", "linux-daemon", "--", "--include-ignored", "--test-threads=1"]
