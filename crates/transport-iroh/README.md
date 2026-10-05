# transport-iroh

The transport interface over a real network.

Six earlier changes built a network that could not reach anything. This is the
first code in the workspace that touches a socket.

`FORMAT.md`-level detail lives in the source; this is the reasoning, and the
gate.

## The gate, first

`DESIGN.md` §0 forbids merging network code without a test against a real-world NAT
edge case. There are two pieces of evidence and they answer different questions:

| | Question | Status |
|---|---|---|
| [`nat-matrix/`](../../nat-matrix/README.md) | Does the binding work through NAT, and fall back correctly? | **Runs, four cases pass** |
| [`nat-matrix/MEASUREMENT.md`](../../nat-matrix/MEASUREMENT.md) | What fraction of *real* connections go direct? | **Not run.** Needs two networks and a phone |

The matrix does **not** achieve a direct path in any case, including the easy
one — Linux masquerading does not reproduce the conditions a real router
provides. So it proves the machinery and not traversal itself, which is exactly
why the second row is the gate and the first cannot stand in for it. The matrix
README explains this at length; it is the most useful thing that work produced.

## What makes this small

**A transport key is an endpoint identity.** DESIGN.md §2.3 fixes device transport
keys as ed25519, which is what iroh identifies endpoints by. So a roster
transport key *is* an endpoint id: the bytes being dialled are the bytes the
roster authorises, with no lookup table between them. Any other arrangement needs
a device-to-endpoint mapping, and that mapping would be a second answer to "who
is this peer", kept outside the signed log and able to disagree with it.

A transport key that is not ed25519 is refused when the endpoint is built, naming
the algorithm — not at the first connection, which would be diagnosed far from
the misconfiguration that caused it.

**Possession is already proven when a connection arrives.** The QUIC handshake
establishes that the peer holds the private half of the identity it presents, and
establishes it *bound to that channel*. The in-memory transports sign a nonce
because they have no channel to bind to; a challenge-and-signature exchange
carried inside an already-established channel proves strictly less — the
signature is not bound to the connection — and costs a round trip that §2.6b's
500 ms activation budget cannot spare.

So this binding runs only the membership half, through `transport::auth::authorize`:
resolve the key to a device **for the transport purpose**, then check the revoked
set. Same authority, same rules, one fewer round trip.

## The relay is named by the roster

The address comes from the signed network parameters and nowhere else. Nothing is
compiled in — a test asserts the crate contains no URL — and no local
configuration overrides it.

§2.5 argues the network suffix must not be a compile-time constant so the choice
stays reversible. The relay is the same kind of choice with a sharper edge:
whoever supplies it learns who talks to whom and when, and can withhold service,
even though the traffic is end-to-end encrypted and it can read none of it. Held
in each node's config, no two nodes need agree and anyone who can write that file
can substitute their own. Changing it is one `set_network` operation.

**An unplanned dividend.** Because the relay is a *network* parameter, every node
already knows every peer's home relay — so `connect(key)` resolves an address
with no discovery service at all. That matters here because the endpoint is built
from iroh's `Minimal` preset rather than its defaults, which would pull in
third-party relays and third-party DNS. §2.8 requires a self-hosted relay; §2.6c
requires that a node speak to no infrastructure the user did not choose.

A network with no relay works over direct paths only, and failing to reach a peer
that needs one is reported as unreachability rather than an internal error.

## The relay's certificate is pinned by the roster too

The address alone does not say which server is the network's relay. A node
contacts the relay before it has authenticated anything, and the ordinary answer
to *is this the right server* — a public certificate authority — is the third
party this network exists to do without. So `relay_cert` sits beside `relay` in
the signed parameters: DER, optional, set at founding.

When it is present the endpoint trusts **that certificate and nothing else**:
`CaTlsConfig::custom_roots`, not `default().with_extra_roots(..)`. The second
would leave every public authority trusted alongside the pin, so anyone able to
have a certificate issued for the relay's address could still stand in front of
it — which is the arrangement being avoided, not a smaller version of it. Only
the relay is affected: under `Minimal` there is no other TLS.

A relay you run yourself now needs no public certificate at all, which was the
practical obstacle to §2.8. A network whose relay does have a publicly signed
certificate may pin nothing and be verified the usual way.

An unusable pin is refused at bind, naming the certificate. It has to be: the
trust store silently ignores what it cannot parse, so the pin would otherwise
become an empty store, and an empty store rejects the real relay exactly as it
rejects an impostor — visible only as every peer being unreachable, with nothing
anywhere pointing at a certificate.

## Addresses this layer is told about

`addresses` reports the endpoint's own direct addresses, and `learned` takes
addresses somebody heard for a peer and offers them on the next dial alongside
the relay rather than instead of it. Both come from the `Transport` trait and
both default to doing nothing; this is the only implementation that does
anything with them.

They exist for §2.9's first path. A network with no relay at all can still reach
a peer whose address was learned — there is a test that does exactly that, and it
is the only way that dial can succeed, so it cannot pass by accident.

The hints decide nothing. They are added to the `EndpointAddr` that is dialled,
the connectivity layer races them against the relay, and the session that
results is authorised from the roster like any other. Unparseable ones are
dropped rather than reported: what an address looks like is this crate's
business, and a caller passing on what it heard has done nothing wrong. Both the
number of peers remembered and the addresses per peer are bounded.

## The one endpoint that accepts a stranger

A device with no roster cannot decide membership, having nothing to decide it
from. So enrolment gets an endpoint of its own, and the waiting side of it
accepts a peer no roster names. That is the only place in this crate where that
happens, and it is an exception to the *check* rather than to the rule behind
it: the peer is granted nothing, the exchange carries no application payload,
the endpoint exists only while a person is enrolling, and everything received
across it is verified afterwards against signatures the peer cannot forge.

**Waiting and admitting are different types.** `Waiting` accepts and has no way
to dial; `Admitting` dials and has no listener at all — it offers no protocol,
so there is nothing for an incoming connection to agree with. That split is not
tidiness. Admitting somebody needs an enrolment endpoint on the machine that
already holds a roster, routes and data, and one that could also accept would
put a door into exactly the machine the ordinary rule protects. No device
holding a roster accepts a peer that roster does not name, through any endpoint,
at any time.

The two protocols cannot be confused: the enrolment ALPN differs from the
session one, so an ordinary peer and an enrolment endpoint never establish at
all. Structural, not a check performed after connecting.

**The channel exports material the confirmation code is bound to.** Both ends of
one exchange export the same value, two exchanges never export the same value,
and neither side can choose it. Every key in a confirmation code is public — the
joining payload is on a screen — so a code over keys alone could be computed in
advance and then matched by grinding key pairs against a space of one million.
Channel material is what stops that, because the value being matched does not
exist until the channel does.

The relay for a waiting endpoint comes from the person starting the enrolment,
since a device with no roster has no signed parameters to read one from. It is
verified the ordinary way first and accepted on sight only when that fails, and
what was accepted is recorded so the network can insist on the same certificate
when it is adopted.

## Framing

The interface promises that what is sent as one payload arrives as one payload,
up to 262 144 bytes. QUIC gives neither for free: datagrams keep boundaries but
are bounded by the path MTU, around 1200 bytes; streams are reliable and ordered
but are byte streams with no boundaries at all.

So: one bidirectional stream per session, each payload behind a four-byte
big-endian length. One stream rather than one per payload, because separate
streams have no ordering relative to each other and the interface promises order.
A declared length is checked against the bound **before** any buffer is reserved.
An oversized payload is refused at the sender, whole; a truncated frame is a
reported failure, never a short payload delivered as if complete.

The stream carries a four-byte opener. QUIC does not surface a stream to the far
end until something is written on it, so a session whose stream stayed silent
until the first payload would leave the accepting side waiting — possibly
forever. It doubles as a check that both ends speak this framing.

**The stream carries payloads only.** Packets — tunnel traffic — travel as QUIC
datagrams. On the stream a tunnel packet inherited order and delivery it never
needed: one lost QUIC packet stalled every tunnel packet behind it, and the TCP
inside the tunnel retransmitted on top of QUIC's own retransmission. Through the
relay, where QUIC itself rides a TCP connection, a mobile network's losses were
recovered three times over. A datagram is lost or delivered, and the traffic
inside recovers as it would on any network.

A datagram holds what one QUIC packet on the path carries — around 1,150 bytes
before the path's MTU is discovered — and a full-size tunnel packet is 1,280, the
least IPv6 allows on a link. So `fragment` cuts a packet into at most four even
pieces behind a six-byte header (`[id: u32][index: u8][count: u8]`), and the
receiver delivers it only when every piece has arrived. The datagram size is read
from the connection at each send, because it changes as the MTU is discovered and
when the session moves between a direct path and the relay.

What a receiver holds for incomplete packets is bounded: 64 packets, 128 KiB, and
one second per packet, checked as datagrams arrive. The oldest go first. A piece
that contradicts its packet — another count, a repeated index, an index beyond
the count — discards the packet. A sender never waits for room: under congestion
a packet is dropped, as a router would drop it.

A peer that does not accept datagrams — a build from before packets — is reported
as such (`PacketsNotAccepted`), rather than seen as silent loss.

## The shared suite passes unmodified

`transport::suite::run_all`, byte-identical to the one the two in-memory
implementations run. That is the whole reason `transport-session` shipped two
implementations rather than one: an interface with a single implementation is an
untested claim about replaceability. A third, radically different implementation
passing the same suite is what turns the claim into a result.

Nothing in the suite needed changing to accommodate this binding.

## A test-only escape hatch

`bind_trusting_any_relay_certificate` exists behind the `insecure-test-relay`
feature, because a relay running inside a test topology necessarily presents a
certificate no authority signed. An ordinary build cannot reach it. A node that
accepted any relay certificate could be steered onto an impostor relay, which
learns who talks to whom and when.

It is no longer the only way to reach a self-signed relay, and that matters more
than it sounds. While it was, any evidence gathered against a real self-signed
relay had to come from a build with verification switched off — and a result
taken that way says nothing about what the shipped program does. Two tests hold
the line: one reaches a pinned self-signed relay on the ordinary path, the other
shows the same relay unreachable when the network pins nothing.

## Vocabulary

iroh 1.x renamed what DESIGN.md §2.1 calls a `NodeId` to `EndpointId`, and
`NodeAddr` to `EndpointAddr`. The model is unchanged; only the names moved. A
reader of §2.1 should not conclude the design drifted.

## Operational note: moving a relay

Changing a network's relay is one `set_network` operation, propagated by
`roster-sync` like any other. But a node that has been offline long enough to
know *only* a relay that is already dead may have no way to reach anyone to learn
the new address.

Mitigated, not solved. §2.9's first path is the local network and does not need
the relay; cached direct endpoints likewise. When moving a relay, keep the old
one answering until nodes have synced.

## Deliberately elsewhere

| Deferred | To |
|---|---|
| Operating the relay: provisioning, TLS, per-key bandwidth and session limits | deployment; §2.8 says `iroh-relay`, self-hosted, never hand-written |
| Finding where a peer is when its relay is not enough | `rendezvous-service`, `local-discovery` |
| Packet-level source validation at the TUN interface | `tunnel` |
| Deciding when to connect, to whom, how often | `windows-daemon` |
