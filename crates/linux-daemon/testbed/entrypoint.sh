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

if [ -z "${TPM2TOOLS_TCTI:-}" ]; then
    exec /usr/local/bin/peerfectlyd "$@"
fi

# With a TPM, stopped as a machine shuts down: the daemon first, then the TPM
# told it is going off. A TPM that loses power without that counts the next
# start as a failed authorisation (TPM 2.0's defence against power-cycling past
# its lockout), so three `docker compose restart`s in a row would lock it out.
/usr/local/bin/peerfectlyd "$@" &
daemon=$!
trap 'kill -TERM "$daemon" 2>/dev/null; wait "$daemon"; tpm2_shutdown -c 2>/dev/null; exit 0' TERM INT
wait "$daemon"
status=$?
tpm2_shutdown -c 2>/dev/null
exit "$status"
