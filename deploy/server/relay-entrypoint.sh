#!/bin/sh
# Starts the relay with the certificate both services read: puts PEERFECTLY_CERT and
# PEERFECTLY_KEY into the relay's configuration, writes it where the read-only image
# allows, and hands over to the relay.
set -eu

cert="${PEERFECTLY_CERT:-/etc/peerfectly/certs/relay.crt}"
key="${PEERFECTLY_KEY:-/etc/peerfectly/certs/relay.key}"
config="${PEERFECTLY_RELAY_CONFIG:-/etc/peerfectly/relay.toml}"
effective=/tmp/relay.toml

# `|` as the delimiter: a path holds slashes, and never a newline or a `|` that a
# person would choose.
sed -e "s|@PEERFECTLY_CERT@|${cert}|g" -e "s|@PEERFECTLY_KEY@|${key}|g" "$config" > "$effective"

exec iroh-relay --config-path "$effective"
