# The relay and the rendezvous, in one image. Built from the repository root:
#
#   docker build -f deploy/server/Dockerfile -t peerfectly-server .
#
# Nothing in it is specific to one host, and it holds no certificate or key:
# those are mounted at run time (see compose.yaml and README.md).

FROM rust:1.95-bookworm AS builder
WORKDIR /src
COPY . .
# Both binaries from this workspace's lockfile, so the relay is the exact
# iroh-relay the workspace is tested against (1.3.0), with the versions of its
# dependencies the workspace resolved. `relay-binary` is how a workspace member
# asks for the `server` feature iroh-relay's own binary needs.
RUN cargo build --release --locked \
        -p rendezvous-server -p iroh-relay \
        --features rendezvous-server/relay-binary \
        --bin peerfectly-rendezvous --bin iroh-relay

FROM debian:bookworm-slim
# The user both services run as, in a group of the same number: the host's key
# is readable by that group and nobody else. No shell to log into, no home.
RUN groupadd --system --gid 10001 peerfectly \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin peerfectly
COPY --from=builder /src/target/release/iroh-relay /src/target/release/peerfectly-rendezvous /usr/local/bin/
COPY deploy/server/relay.toml /etc/peerfectly/relay.toml
COPY --chmod=0755 deploy/server/relay-entrypoint.sh /usr/local/bin/relay-entrypoint
# One setting for both services: where the mounted certificate and key are.
ENV PEERFECTLY_CERT=/etc/peerfectly/certs/relay.crt \
    PEERFECTLY_KEY=/etc/peerfectly/certs/relay.key
USER 10001:10001
# The relay: HTTP for captive portals, HTTPS and QUIC. The rendezvous: HTTPS.
EXPOSE 8080/tcp 8443/tcp 8443/udp 8444/tcp
# The rendezvous by default; the relay's service runs relay-entrypoint.
CMD ["peerfectly-rendezvous"]
