# The relay: a convesso relay, and the key it serves over HTTPS, in one program.
# Built from the repository root:
#
#   docker buildx build -f deploy/server/Dockerfile -t peerfectly-relay --load .
#
# Nothing in the image is specific to one host: the relay's identity and
# certificate are made on first start, in the volume at /data.

FROM rust:1.95-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p relay-server --bin peerfectly-relay

FROM debian:bookworm-slim
# The user it runs as, in a group of the same number. No shell to log into, no
# home: the volume is its only writable place.
RUN groupadd --system --gid 10001 peerfectly \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin peerfectly \
    && mkdir /data && chown 10001:10001 /data
COPY --from=builder /src/target/release/peerfectly-relay /usr/local/bin/
USER 10001:10001
VOLUME /data
# The relay, UDP and TCP; the key, HTTPS. Unprivileged ports: the host publishes
# 443 to 8444.
EXPOSE 8443/udp 8443/tcp 8444/tcp
CMD ["peerfectly-relay"]
