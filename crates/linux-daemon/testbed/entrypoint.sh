#!/bin/sh
# A testbed node: its software TPM, when it has one, then the daemon in the
# foreground as the container's main process — so `docker compose stop` is a
# SIGTERM to the daemon, as `systemctl stop` would be.
set -eu

if [ -n "${TPM2TOOLS_TCTI:-}" ]; then
    mkdir -p /var/lib/swtpm
    swtpm socket --tpm2 \
        --tpmstate dir=/var/lib/swtpm \
        --server type=tcp,port=2321,bindaddr=127.0.0.1 \
        --ctrl type=tcp,port=2322,bindaddr=127.0.0.1 \
        --flags not-need-init,startup-clear \
        --daemon
fi

exec /usr/local/bin/peerfectlyd
