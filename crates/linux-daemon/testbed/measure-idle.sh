#!/bin/sh
# Counts what a testbed node sends and receives while nothing is carried, and
# says what that would be in a month:
#
#   crates/linux-daemon/testbed/measure-idle.sh <node> <peer> <relay address> [seconds]
#
# for example `measure-idle.sh b a 204.216.216.139 300`. Run it from the
# repository root, with the network already up on the node and nothing being sent
# through the tunnel. The peer may be up or switched off: those are the two
# configurations the traffic budget is stated for (see the `session-lifecycle`
# capability, "What a device spends at rest is measured, and bounded").
#
# The counters are nftables rules on the node's real interface, `eth0`, in a
# table of their own that is removed afterwards. Each packet is counted in the
# total and then in the first category it fits, multicast first: a peer's
# announcements come from the peer's own address, and counting them twice would
# make the rest come out negative. `accept` only ends this table's chain; the
# policy is accept anyway, and the node's own firewall table still runs. Only that interface is counted:
# what crosses the tunnel's own interface is the tunnel's payload, and at rest
# there is none. Each destination is counted in both directions:
#
#   peer      the peer's container address, IPv4 — the direct path
#   ipv6      link-local IPv6 — the direct path again, on the addresses iroh
#             also tries; in the testbed only the nodes are on that link
#   rendezvous the rendezvous, on the relay's host: TCP port 8444
#   relay-quic UDP to the relay's host: the address discovery of iroh's net
#             report, a QUIC connection of its own
#   relay     the rest to the relay's host: the relay connection, which is TCP
#   multicast local-discovery announcements
#   rest      everything else on eth0
#
# `relay host` sums `relay` and `relay-quic`, what the transport spends on the
# relay. `not relay` is everything else, the rendezvous included. Until
# `quiet-iroh`, `relay` counted all three.
#
# Bytes are what the kernel counts for the packets, IP header included, which is
# what a data plan counts.

set -eu

if [ "$#" -lt 3 ]; then
    echo "usage: $0 <node> <peer> <relay address> [seconds]" >&2
    exit 2
fi
node=$1
peer=$2
relay=$3
seconds=${4:-300}

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
# Under Git Bash on Windows, Docker wants C:/… rather than /c/…, and with path
# conversion off below it would not get it converted.
if command -v cygpath >/dev/null 2>&1; then
    ROOT=$(cygpath -m "$ROOT")
fi
compose() {
    # Git Bash would otherwise rewrite the container-side paths and addresses.
    MSYS_NO_PATHCONV=1 docker compose -f "$ROOT/crates/linux-daemon/testbed/compose.yaml" "$@"
}

peer_ip=$(compose exec -T "$peer" sh -c "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1" 2>/dev/null || true)
if [ -z "$peer_ip" ]; then
    # A peer that is switched off still has a container; one that was removed
    # has no address to count against.
    echo "cannot read $peer's address: is its container running?" >&2
    exit 1
fi

# `probe`, not `meter`: `meter` is an nftables keyword.
compose exec -T "$node" sh -c "
nft delete table inet probe 2>/dev/null || true
nft -f - <<EOF
table inet probe {
  chain out { type filter hook output priority -300; policy accept;
    oifname \"eth0\" counter comment \"total\"
    oifname \"eth0\" ip daddr 224.0.0.0/4 counter accept comment \"multicast\"
    oifname \"eth0\" ip6 daddr ff00::/8 counter accept comment \"multicast\"
    oifname \"eth0\" ip daddr $peer_ip counter accept comment \"peer\"
    oifname \"eth0\" ip6 daddr fe80::/10 counter accept comment \"ipv6\"
    oifname \"eth0\" ip daddr $relay tcp dport 8444 counter accept comment \"rendezvous\"
    oifname \"eth0\" ip daddr $relay meta l4proto udp counter accept comment \"relay-quic\"
    oifname \"eth0\" ip daddr $relay counter accept comment \"relay\"
  }
  chain in { type filter hook input priority -300; policy accept;
    iifname \"eth0\" counter comment \"total\"
    iifname \"eth0\" ip daddr 224.0.0.0/4 counter accept comment \"multicast\"
    iifname \"eth0\" ip6 daddr ff00::/8 counter accept comment \"multicast\"
    iifname \"eth0\" ip saddr $peer_ip counter accept comment \"peer\"
    iifname \"eth0\" ip6 saddr fe80::/10 counter accept comment \"ipv6\"
    iifname \"eth0\" ip saddr $relay tcp sport 8444 counter accept comment \"rendezvous\"
    iifname \"eth0\" ip saddr $relay meta l4proto udp counter accept comment \"relay-quic\"
    iifname \"eth0\" ip saddr $relay counter accept comment \"relay\"
  }
}
EOF"

echo "counting on $node for ${seconds}s (peer $peer at $peer_ip, relay $relay)..." >&2
sleep "$seconds"

compose exec -T "$node" nft list table inet probe \
    | sed -n -E 's/.*counter packets ([0-9]+) bytes ([0-9]+) (accept )?comment "([^"]+)".*/\4 \1 \2/p' \
    | awk -v seconds="$seconds" '
        # Each label appears once per direction, multicast twice per direction;
        # both directions are summed, as a data plan sums them.
        { packets[$1] += $2; bytes[$1] += $3 }
        END {
            rest_p = packets["total"]; rest_b = bytes["total"]
            split("peer ipv6 rendezvous relay-quic relay multicast", order, " ")
            for (i = 1; i <= 6; i++) { rest_p -= packets[order[i]]; rest_b -= bytes[order[i]] }
            packets["rest"] = rest_p; bytes["rest"] = rest_b
            month = 30 * 24 * 60 * 60 / seconds
            printf "%-11s %10s %12s %14s\n", "", "packets", "bytes", "per month"
            split("peer ipv6 rendezvous relay-quic relay multicast rest total", shown, " ")
            for (i = 1; i <= 8; i++) {
                k = shown[i]
                printf "%-11s %10d %12d %11.1f MB\n", k, packets[k], bytes[k], bytes[k] * month / 1e6
            }
            relay_b = bytes["relay"] + bytes["relay-quic"]
            printf "%-11s %10s %12s %11.1f MB\n", "relay host", "", "", relay_b * month / 1e6
            printf "%-11s %10s %12s %11.1f MB\n", "not relay", "", "", (bytes["total"] - relay_b) * month / 1e6
        }'

compose exec -T "$node" sh -c "nft delete table inet probe 2>/dev/null || true"
