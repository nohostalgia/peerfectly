# rendezvous

Where a device says it can be reached.

`transport-iroh` proved two nodes can find each other and punch through real
NATs — but only because both were told the same relay and the relay knew where
each was. This answers the question a node asks when it wakes up: *where was this
peer last seen, so I can try it directly before falling back to anything?*

[`FORMAT.md`](FORMAT.md) is the wire specification. This is the reasoning.

## Why it exists at all

DESIGN.md §2.6b makes one number the product's main performance metric:

> From switching on to the first useful session: under 500 ms, from cached
> endpoints, **without waiting for the rendezvous**.

Both halves matter. The cached endpoint is what makes 500 ms possible, and the
cache has to be filled from somewhere. This fills it — and then gets out of the
way, which is why the client here caches nothing.

## What this service is allowed to be

§6.1 states it exactly, and the whole design follows from it. A compromised
rendezvous:

| Cannot | Why not |
|---|---|
| inject devices | membership is the roster's; a record is not evidence of it |
| alter a record | the device signed it, and an altered one fails verification |
| produce a record that verifies | it holds no key any client accepts |

| Can | Consequence |
|---|---|
| censor | the network must work when this is unreachable |
| delay | so freshness cannot be based on anything it reports |
| observe | it sees who publishes and who asks |

Those three are **accepted**, not defended against. §8 is blunt about what
follows: failing to connect while standing half a metre from a node, because a
server was down, would be an absurd failure for a product sold on sovereignty.

## Signatures do everything

§2.8: no authentication. No accounts, no tokens, no notion of who is calling. A
publication is accepted because the signature verifies under the key it is filed
under; a fetch is served to anyone.

There is nothing in it to steal, nothing to phish, and no credential whose loss
would mean anything. That is the point of the design, not an omission from it.

## The device signs its own record

Nothing in a record requires authority. Current addresses, online state and
exposed ports are ephemeral facts a device knows about itself — §4.1 keeps them
out of the roster for exactly that reason, because the roster holds only what an
admin must decide.

A record signed by an admin would put an authority in the path of a fact no
authority is needed for, and a device could not update its own address while the
admin was away.

**With the transport key, never the signing key.** The transport key is what a
peer authenticates the resulting session against, so the key that says *I am
here* is the key that will prove *I am me*. Signing with the other would mean
publishing an address under one identity and answering under another, with the
join between them living only in the roster — a lookup an attacker would enjoy
confusing. It also keeps the signing key out of a hot path, since §2.3 allows it
to live behind a biometric prompt.

## The sequence is the only freshness rule

A record is accepted only if its sequence exceeds the one already held — at the
service, and again at the client against the highest it has itself accepted.

**There is no timestamp, deliberately.** `DESIGN.md` §0 forbids timestamps
deciding validity, and both ways of adding one fail here:

- a **device-signed** time is signer-chosen, so a device with a wrong clock
  silently stops being reachable;
- a **server-recorded** time trusts the party §6.1 says may delay — it can lie in
  exactly that field.

The cost is real and small. A client that has never seen a key before can be
served an old record; it then tries a dead address, and §2.9 opens the relay in
parallel, so the session is already forming while that probe fails. A stale hint
costs one wasted packet, not a failed connection.

### A restart is not a rollback

Storage is in memory. Every record is ephemeral by §4.1's definition and is
republished by its device, so a restart costs one publication interval of
staleness rather than correctness. A database would add backups, migrations and
disk exhaustion to a service whose entire argument is that there is nothing in it
worth stealing.

The consequence is stated rather than hidden: a restart resets every sequence, so
a device whose record was at 40 can publish 41 into an empty store. **The
client's own rule is what protects it**, and that survives the service — a client
that saw 40 refuses anything at or below it.

## Equivocation is refused, not resolved

Two different records at one sequence are **both** refused. A device that signed
both has equivocated, and choosing a winner would hide the evidence —
`equivocation-detection` will want it.

## A published address is a hint, never an authority

What comes back says *where to try*, never *who a peer is*. A session opened to
an address learned here is authenticated exactly as one learned any other way,
and a record naming an address where a stranger answers produces no session.

The client **caches nothing and dials nothing**. §2.6b requires a cached endpoint
to be usable without waiting for the rendezvous, which only holds if the cache
lives above this crate — a client that cached internally would make the 500 ms
budget depend on this crate's timing. `windows-daemon` owns the cache and the
schedule.

Addresses are opaque strings, unparsed. The transport decides what an address
means, and parsing one here would recreate the coupling `transport-session`'s
abstraction exists to avoid.

## Limits, from the first commit

§2.8 requires them on day one rather than as a later hardening pass, because the
first day this is public is the first day it is a target. Record size, addresses
per record, publication rate per key, keys per source address, and one global
bound on total records.

Every limit but the last is **per key or per source**, so exhausting one costs
nobody else anything. Reaching the global one is **reported**, never a silent
discard: a store that quietly drops is a store that quietly stops working.

A limit refusal is kept distinguishable from a rejected record, and survives to
the wire as `429` rather than `4xx`. A rate-limited publisher is behaving
normally and will succeed later; one sending records that do not verify never
will, and a client that retried it forever would be hammering the one piece of
shared infrastructure the project runs.

## Running it beside the relay

The relay from `transport-iroh` already runs on a host somewhere; this belongs on
the same one. Both are small, and §2.8 puts the STUN function there too — the
point is that a network depends on **one** machine its owner controls, not
several.

It listens on plain HTTP and holds no secret, so it can sit behind whatever
terminates TLS for the relay, or behind nothing. The content is signed either
way; TLS here hides *who is asking*, which §6.1 already accepts the service
itself can see.

Two things to get right, both the same shape as the relay's:

- **Open the port in both firewalls.** On a cloud host that usually means a
  security group *and* the instance's own rules. Only one of them failing looks
  exactly like the service being down.
- **Build a static binary if the host is older than the build machine.** Same
  glibc trap the relay hit; `nat-matrix/Dockerfile.static` is the pattern.

There is nothing to back up. Every record is republished by its device, so a lost
store costs one publication interval.

## Deliberately elsewhere

| Deferred | To | Why |
|---|---|---|
| Storing the roster, which §4.7 contemplates | `roster-sync` | a second path into the roster is a second thing to eclipse |
| Finding peers on a LAN | `local-discovery` | §8: the network must work with the internet off, so nothing there may depend on this |
| Caching, scheduling, when to publish | `windows-daemon` | it knows the session lifetimes and the power constraints |
| TLS, supervision, deployment | operations | the content is signed, so transport confidentiality is a deployment choice |
