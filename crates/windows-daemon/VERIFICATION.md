# Verification on a real machine

What the automated suite cannot show, and the commands that show it.

**Run so far**: 56 of 88. Every other result reads `not run`. That is the honest
state, written down rather than left blank so an unverified behaviour cannot be
mistaken for a tested one.

**On 2026-09-16 the command line was split into three views** — `status` describes
the networks, `peers` the devices, `address` an address — and what each prints was
redrawn. Every **Expect** below names the wording as it is now. Every **Result**
records what was seen on its date and is left as it was written: a result quoting
`reachable, direct` was true when it was taken, and rewriting it would be inventing
an observation nobody made.

This is the same split `transport-iroh` needed for NAT: a reproducible automated
body of evidence, and a separate real-world measurement which is the one that
actually settles the question. There, the automated matrix was silently
contaminated for days and only the real measurement caught it.

**On 2026-10-03 the product was renamed from `mynet` to `peerfectly`** (`rename-to-peerfectly`),
protocol included: nothing before that date speaks to anything after it. Commands and **Expect**
lines use the new names. **Result** lines keep the names they were taken with, because rewriting
them would be inventing an observation nobody made.

## Why none of this can be automated

Every step needs at least one of: Administrator, a signed kernel driver, a second
machine, a second user account, or a desktop session. A CI runner has none of
them. Making the suite "cover" this would mean weakening what it checks until it
passed, which is worse than admitting the gap.

## Observed so far, on the development machine

Partial, on **A** only, during development. Recorded because it is what is known —
not as a substitute for the steps below.

- The daemon starts, reports its driver, and creates no adapter until asked.
- `mynet up` succeeded: adapter created, address assigned, route installed, NRPT
  rule written, resolver bound.
- `ping nas.mynet.internal` answered — so the rule steers the suffix, the resolver
  answers from the roster, and the stack treats the address as local.
- A bring-up that failed at the resolver rolled everything back and said so:
  *"failed while starting the resolver … nothing was left on the machine"*.

None of it exercised a packet crossing between two machines.

---

# Before you start

## What you need

- Two Windows machines. **A** is the founder (`nas`), **B** the other (`laptop`).
  A Hyper-V VM is fine for everything except step 1, where real hardware is more
  convincing.
- **Administrator on both.** Today the daemon *and* the command line both need an
  elevated console — see step 8 for why, and why that is a defect rather than the
  design.
- `wintun.dll` from wintun.net, beside `peerfectlyd.exe`.
- A second user account on A, for steps 8 and 9.

Substitute your own values throughout:

| | this deployment |
|---|---|
| suffix | `peerfectly.internal` |
| prefix | `fd6c:4fbc:9c79:d144::/64` |
| A | `nas.peerfectly.internal` |
| B | `laptop.peerfectly.internal` |

## Build

```
cd <the repository root>
$env:RUSTFLAGS = "-C target-feature=+crt-static"
cargo build --release -p programs
```

The static C runtime matters: without it the binaries need the VC++
redistributable, which a clean machine B will not have.

## Found the network, and join the second device

Two commands, and a person comparing six digits. No file is copied between the
machines and nothing has to reach the joining device beforehand.

### On A: found the network

```
.\peerfectly.exe found nas --suffix peerfectly.internal --relay https://<your relay> --fetch-relay-cert
```

Add `--rendezvous <url>` if you run one. Omit `--relay` entirely for a LAN-only
test — enough for every step except a cross-network step 1.

`--fetch-relay-cert` asks the relay for the certificate it presents, checks that
a verifying client could actually accept it, shows the SHA-256 fingerprint, and
pins it once you type `yes`. The pin goes into the **signed** network parameters,
so every device that later reads this roster trusts that certificate and no
certificate authority.

Without a pin nothing reaches a relay you run yourself: the handshake fails, no
device registers a home relay, and every peer shows as unreachable with nothing
in the output mentioning certificates. That is the failure seen between these
two machines on 2026-09-09.

**What the fingerprint is for.** Fetching it trusts whoever answered at that
address in that moment. Before typing `yes`, compare what is on screen with what
the relay host says about its own certificate:

```
openssl x509 -in <the relay's cert file> -noout -fingerprint -sha256
```

If you already have the certificate file on this machine, pass it directly
instead: `--relay-cert relay.pem` takes PEM or DER.

Founding twice is refused, and says how to start over on purpose. That is not a
flag: losing a network by typing a command twice is not a thing this offers.

### On B: start waiting

```
.\peerfectly.exe join --relay https://<your relay>
```

Add `--name <name>` to propose one; without it the machine's own name is
proposed. The admin decides the final name and the role either way — a joining
device cannot ask to be an admin, and the payload has no field for it.

B prints a QR code and a line beginning `peerfectly-join-v1:`, then waits. If the
relay's certificate is not publicly verifiable, B says so and shows the
fingerprint it accepted — **the network it joins must pin that same certificate
or B will refuse it**.

Carry that line to A. Photograph the code, paste the text, whatever is
convenient: it carries no secret, and holding it grants nothing.

### On A: admit it

```
.\peerfectly.exe admit peerfectly-join-v1:<what B printed>
```

A reaches B, checks that B holds **both** of the keys it presented, and shows:

```
  device asking to join:  laptop
  its signing key:        AB:CD:...
      004217
```

**Now look at B's screen.** It is displaying six digits of its own.

- If they are the same number, answer `yes` on A, then type those digits into B.
- If they differ, answer `no`. You are not talking to the machine in front of
  you, and nothing has been signed.

Nothing is signed until you answer on A, and B adopts nothing until you type the
digits into B. Either refusal leaves both machines exactly as they were.

### Both machines agree

```
.\peerfectly.exe status          # run on both, once the daemons are up
```

**Both must list the same two devices with the same addresses.** If they
disagree, stop — that is a derivation bug and nothing below will mean anything.

B holds the whole roster, not only the admission: every device appears together.
B keeps its own `identity` file, which never moves; the roster is public, the
identity is not.

## Pin the driver

The daemon refuses an unpinned driver and prints the digest. Before pasting it,
check what you are about to pin:

```
(Get-FileHash .\wintun.dll -Algorithm SHA256).Hash.ToLower()
Get-AuthenticodeSignature .\wintun.dll | Format-List Status, SignerCertificate
```

`Status` must be `Valid` and the signer `WireGuard LLC`. Then paste the printed
line inside the brackets of `PINNED` in `platform/driver.rs`, rebuild, and **copy
the rebuilt `peerfectlyd.exe` and the same `wintun.dll` to B** — the pin is compiled in,
and a separately downloaded copy has a different digest.

Record what was pinned:

| | |
|---|---|
| Wintun version | *not recorded* |
| SHA-256 | *not recorded* |
| Authenticode | *not recorded* |
| Pinned by / date | *not recorded* |

## Start the daemon

On each machine, in an **elevated** console:

```
.\peerfectlyd.exe
```

It stays in the foreground — it owns the tray icon and pumps its message loop
there. Use a second elevated console for `peerfectly`.

Expect a line naming the driver. If it says the network will not come up, the
driver is missing or unpinned, and nothing below will work.

---

# The steps

## 1. A packet crosses between two real machines

**Proves** the adapter carries packets, and that `tunnel`'s rules hold over a real
device rather than only the in-memory one. **The only step that exercises the
gateway** — a ping to a machine's own address never enters the adapter.

On **A** and **B**:

```
.\peerfectly.exe up
.\peerfectly.exe status
```

Then from **B**:

```
ping nas.peerfectly.internal
ping fd6c:4fbc:9c79:d144:38b6:25f1:bb3a:15de
.\peerfectly.exe peers
```

**Expect** replies, and `peers` showing the other device's entry reading
`reachable   yes` marked `(now)` rather than *last known*.

**Result**: run, and it passed — with one defect found on the way.

Two real machines, A the founder and B joined to it over the relay at
`https://203.0.113.10` with its certificate pinned. Addresses
`fd61:42d3:a6c7:1f9b:9165:e7bb:f5c8:b793` (A) and
`fd61:42d3:a6c7:1f9b:a155:1fc1:6f5c:504f` (B).

What was run, in order:

- `mynet found` on A, `mynet join --relay` on B, `mynet admit` on A. The six-digit
  confirmation code matched on both screens and the admission was signed. This is
  the whole of `enrollment-flow`'s task 11.1, which was archived as not done.
- `mynet up` on both. `peers` then read **`not reachable (now)`** on both, and both
  daemons recorded `the peer is not a member of this network` — in each direction.
- `mynet down` and `mynet up` on both. Within seconds `peers` read reachable.
- `ping` from A to B: replies.

**The ping is the result; the cycle in the middle is a defect.** The transport
authorises against a `RosterState` captured when the tunnel came up and never
updated after — `IrohTransport::update_state` exists and is called by no
production code, and `Transport` does not declare it, so the daemon holding an
`Arc<dyn Transport>` could not call it if it tried. Every admission will need the
same down/up until that is fixed, and a *revocation* will not take effect at all
until then, which is the serious half. See the `membership-freshness` change.

Two further things this step showed, neither fatal to it:

- Local discovery did not work, on a shared LAN, with `os error 10065`
  (`WSAEHOSTUNREACH`). `set_multicast_if_v4` is called nowhere in the workspace, so
  the outgoing interface is left to the routing table — which by then carries the
  daemon's own adapter. All traffic fell back to the relay. Also in
  `membership-freshness`.
- B answered the ping only after an inbound ICMPv6 rule scoped to the `mynet`
  interface was added. Windows blocks echo requests on a new, unidentified
  network by default; this is the platform behaving as documented, not a defect,
  but it is what a person hits first and it belongs in the procedure above.

The reverse direction — a connection *unsolicited* from B to A — was not run. The
echo replies prove the tunnel carries traffic both ways; they do not prove A
accepts an unsolicited inbound packet, which needs the same firewall rule on A.

**Both defects above are now closed, and the closure was checked on these same two
machines.** A device admitted while the tunnel stayed up on the admitting machine
became reachable with no `down`/`up` on either side, which is the failure that
prompted the cycle recorded above. Local discovery worked over the shared LAN with
the tunnel up, where before it reported `os error 10065` and every path fell back
to the relay. Step 11 records the revocation half.

What the automated suite could not have caught is why this is written down: both
defects were invisible to it, one because every test supplied the roster state
itself — the very thing the daemon could not do — and the other because the
machine, not the code, is what makes it appear.

## 2. The address, the route, and no default route

**Proves** §2.6's split routing on a real routing table.

With the tunnel **up**:

```
Get-NetIPAddress -AddressFamily IPv6 | Where-Object IPAddress -like 'fd6c:*' |
    Format-Table IPAddress, InterfaceAlias, PrefixLength, AddressState

Get-NetAdapter | Where-Object InterfaceDescription -like '*Wintun*' |
    Format-Table Name, ifIndex, Status, MtuSize

Get-NetRoute -AddressFamily IPv6 |
    Where-Object { $_.DestinationPrefix -like 'fd6c:*' -or $_.DestinationPrefix -eq '::/0' } |
    Format-Table DestinationPrefix, InterfaceAlias, ifIndex
```

**Expect**:

- the address present, `AddressState` **`Preferred`** — `Tentative` would mean
  duplicate address detection was not skipped
- `MtuSize` **1280**
- exactly one route for the prefix, on the Wintun interface
- **no `::/0` on the Wintun interface.** A default route on your physical adapter
  is normal and is not ours.

**Result**: not run.

## 3. Everything is removed on the way down

```
.\peerfectly.exe down

Get-NetIPAddress -AddressFamily IPv6 | Where-Object IPAddress -like 'fd6c:*'
Get-NetRoute -AddressFamily IPv6 | Where-Object DestinationPrefix -like 'fd6c:*'
Get-DnsClientNrptRule | Where-Object Namespace -like '*peerfectly*'
Get-NetAdapter | Where-Object InterfaceDescription -like '*Wintun*'
Resolve-DnsName nas.peerfectly.internal -Type AAAA
```

**Expect** the first four to return nothing, and the resolve to **fail**. The
resolver binds inside the tunnel, so with the tunnel down it should not exist.

**Result**: not run.

## 4. Names resolve, and only under the suffix

**Proves** the NRPT rule is scoped, and that names come from the signed roster
rather than from reachability.

With the tunnel **up** on A, and **B switched off**:

```
Get-DnsClientNrptRule | Where-Object Namespace -like '*peerfectly*' |
    Format-List Namespace, NameServers, Comment

Resolve-DnsName nas.peerfectly.internal        -Type AAAA
Resolve-DnsName laptop.peerfectly.internal     -Type AAAA
Resolve-DnsName nosuchname.peerfectly.internal -Type AAAA
Resolve-DnsName example.com               -Type A
```

**Expect**:

- `Namespace` is `.peerfectly.internal`, `NameServers` is A's own overlay address
- `nas` and `laptop` both resolve — **`laptop` while B is switched off**, because
  names come from the roster, not from reachability
- `nosuchname` gives NXDOMAIN
- `example.com` resolves normally, through the system resolver

**Result**: not run.

## 5. A killed daemon leaves nothing behind

**The step that covers what ordinary cleanup cannot**, and the one most likely to
find something.

```
.\peerfectly.exe up
taskkill /F /IM peerfectlyd.exe

Get-NetRoute -AddressFamily IPv6 | Where-Object DestinationPrefix -like 'fd6c:*'
Get-NetAdapter | Where-Object InterfaceDescription -like '*Wintun*'
Get-DnsClientNrptRule | Where-Object Namespace -like '*peerfectly*'
Resolve-DnsName nas.peerfectly.internal -Type AAAA
```

**Expect** the adapter and its route to be **gone** — they die with the process,
which is a property of Windows rather than of our shutdown path. The NRPT rule
**may survive**; that is precisely the case the startup sweep exists for.

Then:

```
.\peerfectlyd.exe
```

**Expect** it to print *"removed a resolution rule left by an earlier run"*, and:

```
Get-DnsClientNrptRule | Where-Object Namespace -like '*peerfectly*'      # nothing
```

**Result**: not run.

## 6. Nothing reaches infrastructure while the network is off

**Proves** §2.6c — the property the product is sold on.

The daemon holds no transport while down, so the simplest check is whether it owns
a socket at all:

```
.\peerfectly.exe down
$daemon = (Get-Process peerfectlyd).Id
Get-NetUDPEndpoint  -OwningProcess $daemon -ErrorAction SilentlyContinue
Get-NetTCPConnection -OwningProcess $daemon -ErrorAction SilentlyContinue
```

**Expect nothing.** Not "a little traffic" — no sockets at all, because there is
no transport to own one.

Then:

```
.\peerfectly.exe up
Get-NetUDPEndpoint -OwningProcess $daemon | Format-Table LocalAddress, LocalPort
```

**Expect** UDP endpoints to appear.

Stronger, with Wireshark: capture on the physical adapter filtered to the relay's
address, leave it ten minutes with the tunnel down, confirm silence.

**Result**: not run.

## 7. The MTU, exercised by a transfer

**Proves** the adapter's MTU sits below what the transport carries. A ping does
not test this — fragmentation failures look like packet loss and get diagnosed as
the wrong thing entirely.

With both machines up, from B (needs file sharing enabled on A):

```
Measure-Command { Copy-Item \\nas.peerfectly.internal\C$\<a-large-file> C:\temp\ }
```

Any large transfer over the overlay will do — `scp` to an SSH server, a download
from a web server on A. Record **what was transferred and how long it took**, not
that "it worked".

```
ping -6 -l 1200 nas.peerfectly.internal
ping -6 -l 1400 nas.peerfectly.internal
```

The second should fail or fragment: the link is 1280.

**Result**: not run.

## 8. Another user cannot reach the control pipe

**Partly known already, and it is a defect.** With the daemon elevated, even your
*own* unelevated console is refused with `os error 5`: Windows gives an object
created by a high-integrity process a high-integrity label, and a
medium-integrity process may not write to it.

That is why every command needs elevation today. It is a deployment problem rather
than a property of the commands, and the fix — an explicit security descriptor on
the pipe — belongs with the change that makes this a service.

What still needs checking is the **other user**:

```
# from a second account, or:  runas /user:<other-account> cmd
.\peerfectly.exe status
```

**Expect** refusal. If a different user can reach it, the pipe needs its
descriptor written explicitly, and the claim in `pipe.rs` is wrong.

**Result**: not run.

## 9. State is not readable by another user

**Proves** what the daemon *relies on* rather than sets: the ACL that
`%LOCALAPPDATA%` inherits.

```
icacls $env:LOCALAPPDATA\peerfectly
```

**Expect** `SYSTEM`, `Administrators` and this user only — no `Users`, no
`Everyone`. Observed on the development machine as exactly those three.

Then from the second account, try to read
`C:\Users\<first-user>\AppData\Local\peerfectly\`. **Expect** access denied.

**Result**: not run.

## 10. The tray

**Proves** the message pump is on the right thread. Getting that wrong gives an
icon that appears and then ignores clicks — a failure that looks like a hang.

With a desktop session: start `peerfectlyd`, run `peerfectly up` from a console and watch
the icon change; move traffic across the tunnel to keep the runtime busy, then
open the tray menu; choose **Stop**.

**Expect** the icon to track the state, the menu to open promptly under load, and
stopping to leave no address, route or rule — check as in step 3.

**Result**: not run.

## 11. A device is expelled, and stops being reachable

**Proves** the one thing membership is for. Until this change there was no command
that could revoke anything: every layer beneath could express and enforce a
revocation and nothing a person typed reached them, so a lost or stolen device
stayed a member for as long as the network existed.

It also proves the half of the freshness defect that matters. A transport deciding
from roster state captured at bring-up goes on admitting a device the roster has
expelled — and unlike the admission half, nobody would see that happen.

With both machines up and a session open, on **A**:

```
.\peerfectly.exe peers
.\peerfectly.exe revoke <the other device's name> <why>
```

**Expect** the revoked device to be gone from `peers` at once, with no restart on
either machine, and **B** to notice within seconds that it has been removed.

Then check the refusals, none of which may sign anything:

```
.\peerfectly.exe revoke <a name nobody holds> a reason
.\peerfectly.exe revoke <this machine's own name> a reason
.\peerfectly.exe revoke <a real name>
```

**Expect** three refusals: no such device; revoking this device would expel the
machine from a network it would go on holding a roster for; and a revocation needs
a reason.

**Result**: run, and it passed.

Run by the operator on the two machines, with the binaries built from this change.
Reported as working: the revocation took effect with no restart on either side, and
the device rejoined afterwards.

**What this record does not contain** is the console output, which was not captured.
The three refusals above are covered by automated tests; what only these two
machines could show — that a revocation signed on one closes the session and reaches
the other — is recorded on the operator's word.

The rejoin costs the device its identity: it comes back with a new key and a new
address, and the revocation stays in the log, which is append-only. That was chosen
deliberately for want of a third machine, not worked around.

## 12. A daemon that has never joined reaches nothing

**Proves the one guarantee this daemon gives up structurally.**

Until `rosterless-daemon`, "the daemon contacts nothing until a person asks" held
by construction: a daemon with no tunnel had no transport and no endpoint, so
there was nothing that *could* speak. The daemon now runs before any network
exists and opens an enrolment endpoint on request, so the guarantee is a rule the
code keeps rather than a shape it has. **No test in the suite can observe this**:
they all run inside the process that would be doing the talking.

The daemon reaches infrastructure in exactly two circumstances — while the tunnel
is up, and while a person's request is in flight. Everything below checks the
gaps between them.

On a machine that has **never** been founded or joined, with no `%LOCALAPPDATA%\peerfectly`:

```
.\peerfectlyd.exe
.\peerfectly.exe status
```

**Expect** the daemon to run, and status to say this device has no network and name
both `peerfectly found` and `peerfectly join`. No adapter, no route, no resolution rule —
check as in step 3.

Then, with the daemon running and nothing asked of it, capture for a minute:

```
pktmon start --etw -m real-time
```

**Expect** nothing to any relay, any rendezvous, and no DNS lookup of either.

Then start a join, abandon it, and capture again:

```
.\peerfectly.exe join --relay <the relay>     (then answer no, or Ctrl-C)
```

**Expect** the traffic to stop when the join ends. A join that finishes leaves the
roster in hand and an endpoint still registered at a relay; if that endpoint is
not closed, the device stays registered with the tunnel down — and **nothing in
the report would show it**.

Finally, on two machines with their daemons running throughout:

```
.\peerfectly.exe found <name> --relay <url> --fetch-relay-cert
.\peerfectly.exe up
```

and on the second:

```
.\peerfectly.exe join --relay <url>
```

**Expect** both to work with **no `down`, no `stop` and no restart on either side**.
That is the whole point of the change.

**Result**: not run.

## 13. A revocation is owed to a named device, and the count is honest

What the automated suite cannot show: that the report a person actually reads,
on a real machine, across a real reboot, says the true thing about a revocation.
Every layer of it is tested in `tests/propagation.rs`; none of those tests can
reboot Windows or switch off a second machine.

**On A, with B switched off**, expel a device and read the report:

```
.\peerfectly.exe revoke <name> "the machine was lost"
.\peerfectly.exe status
```

**Expect** the report to name **B** among the devices that have not confirmed it,
with a count of operations and the line about leaving the tunnel up. Not a bare
number, and not silence.

Then, still with B off:

```
.\peerfectly.exe down
```

restart the daemon, and:

```
.\peerfectly.exe status
```

**Expect** the same row, naming B. Before this change `down` emptied the queue and
a restart began with an empty one, so both of these reported nothing waiting while
the revocation had reached nobody.

Finally start **B**. **Expect** A's row for B to clear by itself, with no command
typed on either machine, and B's derived membership to exclude the revoked device.

**Result**: not run.

## 14. A revocation brings the network up by itself

**On A, with the tunnel down**:

```
.\peerfectly.exe down
.\peerfectly.exe revoke <name> "the machine was lost"
```

**Expect** the network to come up without `up` being typed, and the report to say
so — this is the auto-activation every other administrative action already had and
revoking did not.

**Result**: not run.

## 15. Online, a revocation lands in seconds

**On A and B, both up and connected**, revoke a third device on A and watch B.

**Expect** B's derived membership to exclude it within seconds rather than at the
next reconnect, and A's report to clear its row for B by itself. This is the
recurring reconciliation and the pressing interval doing their work; before this
change the re-offer had no caller at all, so a push that failed waited for the
session to drop.

**Result**: not run.

## 16. Two networks on one machine, side by side

The change's whole claim, and the one thing no automated test can show: two real
adapters, two real resolvers and two real relays on one Windows machine.

On **A**, found one network and join another from **B**:

```
.\peerfectly.exe found casa --relay <url> --fetch-relay-cert
.\peerfectly.exe up casa
.\peerfectly.exe join lavoro --relay <url>
.\peerfectly.exe up lavoro
.\peerfectly.exe status
```

**Expect** `status` to name both, each with its own address, its own relay and its
own peers. **Expect** `ipconfig` to show two adapters, `peerfectly casa` and
`peerfectly lavoro`, and each to resolve only its own names:
`<device>.casa.internal` from the first, `<device>.lavoro.internal` from the
second, and neither answering for the other's suffix.

**Result**: not run.

## 17. Taking one network down leaves the other carrying traffic

**On A, with both up**:

```
.\peerfectly.exe down casa
.\peerfectly.exe status
```

**Expect** `casa` reported down and `lavoro` still up; a ping across `lavoro` to
still answer; and `casa`'s adapter, address, route and name-resolution rule to be
gone while `lavoro`'s remain. Check the rule with
`Get-DnsClientNrptRule` — there should be exactly one left, for `lavoro`'s
suffix.

This is the question the change exists to answer. Before it, there was one
adapter, one rule and one tunnel, and `down` took the lot.

**Result**: not run.

## 18. The two networks cannot reach each other

**On A, holding both**, take a device that is a member of `lavoro` and try to
reach it from a member of `casa`, by name and by address.

**Expect** both to fail: the name not to resolve at all, and the address to be
unroutable rather than reaching anything. Then check the reverse.

The automated suite asserts the five separate reasons this holds. What it cannot
show is that a real Windows routing table, a real NRPT rule and two real
adapters agree with them.

**Result**: not run.

## 19. A network that is down reaches no infrastructure while another is up

**On A**, with `casa` down and `lavoro` up, capture traffic for two minutes and
filter for `casa`'s relay and rendezvous.

**Expect** nothing for `casa` at all — no relay registration, no rendezvous
publish, no multicast announcement carrying its network id — while `lavoro`'s
traffic continues.

§2.6c used to be a property of the daemon: with the tunnel down there was no
transport to speak through. It is now a property **per network**, which is a
weaker structural guarantee and needs the capture to stand behind it.

**Result**: not run.

## 20. A device that already held a network keeps it

**On a machine that ran the previous version and holds one network**, install
this one and start the daemon.

```
.\peerfectly.exe status
```

**Expect** the network still held, under a name taken from its own suffix, with
the same device identity and the same peers as before. **Expect**
`%LOCALAPPDATA%\peerfectly\networks\<name>\` to hold the identity, the roster log
and the endpoint cache, and the old copies in `%LOCALAPPDATA%\peerfectly\` to be
gone rather than left as a second set.

The automated test covers the move. What it cannot cover is a real profile, a
real DPAPI-sealed identity and a real roster that has been in use.

**Result**: not run.

## 21. Each peer's IPv4 address is one host route, and nothing wider

With a network up whose peer holds an IPv4 address:

```
.\peerfectly.exe status
route print -4
.\peerfectly.exe down <network>
route print -4
```

**Expect** `ipv4` beside this device's address in `status` and the peer's beside
its own in `peers`, one `/32`
(`255.255.255.255`) for the peer on the network's adapter, this device's own `/32`
on it, no route for the network's range as a whole, and no default route through
any peerfectly adapter. **Expect** all of it gone after `down`, and every other
network's untouched.

**Result**: run, 2026-09-15, passed. `prova-tel` up: `ipv4: 100.117.31.3`, the phone
`100.99.120.85`; `route print -4` showed `100.99.120.85 255.255.255.255 On-link
100.117.31.3` and the device's own `/32`, no `100.64.0.0/10`, and the only `0.0.0.0`
through the Wi-Fi gateway. After `down prova-tel` both rows were gone and `alarm`'s
`100.123.155.124` was still there. The phone opened
`http://pc.prova-tel.internal:8000` in Chrome, on Wi-Fi and on mobile data, from a
server bound to `0.0.0.0`; ping and TCP over IPv4 crossed in both directions
(recorded in the Android client's verification).

## 22. A peerfectly adapter never outranks the machine's own networks for multicast

```
Get-NetIPInterface -AddressFamily IPv4 | ? InterfaceAlias -like "peerfectly*"
route print -4 | findstr "224.0.0.0 255.255.255.255"
```

**Expect** every peerfectly adapter at interface metric 9000 with automatic metric
disabled, and the adapters' `224.0.0.0/4` and `255.255.255.255` rows weighted above
every physical adapter's — including an adapter whose device holds no IPv4 address
there, which Windows gives a `169.254.0.0/16` address.

**Result**: run, 2026-09-15, passed after two fixes. The first build left the automatic
metric: the adapters' multicast and broadcast rows were at 261 against the Wi-Fi's
291, so an application sending mDNS without naming an interface would have sent it
into the tunnel. Weighing the interface when the IPv4 address was assigned moved
them to 9256, but a network whose own address was withheld got a link-local
`169.254.x.x` address at metric 5 and brought the rows back. Weighing at adapter
creation fixed that; turning the link-local address off in the same call was
refused with error 87, so the address stays, at 9256.

## 23. A peer conflicting with this machine's network is withheld and said

Found a network in the range of the machine's own Wi-Fi, admit a device, bring both
up:

```
.\peerfectly.exe found <network> --name pc --relay <url> --fetch-relay-cert --ipv4-range 192.168.1.0/24
.\peerfectly.exe admit <payload> --network <network>
.\peerfectly.exe status
```

**Expect** the founding to say every device derives its IPv4 address in that range
and that older devices cannot read the network; this device's `ipv4:` and the peer's
to read `withheld here: it conflicts with the local subnet 192.168.1.0/24`; no IPv4
address or route for either on the adapter; the peer still reachable by name over
IPv6.

**Result**: run, 2026-09-15, passed. `prova-v4` founded with `--ipv4-range
192.168.1.0/24` on a machine at `192.168.1.9/24`: the warning printed, this device
derived `192.168.1.250` and the phone `192.168.1.58`, and both read `IPv4 … withheld
here: it conflicts with the local subnet 192.168.1.0/24` with the phone `reachable
(now)`. No `192.168.1.250` was assigned. Networks founded without the flag (every
earlier one) read addresses in `100.64.0.0/10` and their parameters are unchanged.

## 24. Tunnel traffic is not held up behind the stream

With `prova-tel` up on the desktop and the phone, and one 10 MB file served from the desktop:

```
.\peerfectly.exe peers prova-tel    # the phone's entry reads "reachable   yes, direct" or "yes, via relay"
```

**Expect** the phone to fetch the file through the overlay much faster on a direct path than
before the change, with no multi-second stalls in pings from the desktop, and the path shown on
both devices.

**Result**: run, 2026-09-15 and 2026-09-16, passed on a direct path and not improved through the
relay. The same measurements, recorded in full in the Android client's verification:
- Wi-Fi, direct: the phone's 10 MB fetch went from 9–14 s to under 2.1 s, and the desktop's
  pings from a 2.9 s worst case to 247 ms;
- mobile data, via relay: the fetch stayed at 15–50 s, and the desktop's pings lost 16%.

## 25. No session travels over a tunnel this machine carries

With a network up on the desktop and the phone, and the daemon started with `RUST_LOG=iroh=debug`
and `PEERFECTLY_LOG` pointing at a file:

```
ping -n 150 -w 20000 <the phone's overlay address>   # and, on the phone, the same outside the tunnel
findstr "path::selected holepunching Abandoned" <the log>
```

**Expect** hole punching to keep opening a path between the two overlay addresses — the transport
enumerates every interface and cannot tell a tunnel adapter from any other — and **no**
`path::selected` event naming one. A session on a path through the machine's own tunnel can only
be served by itself, and freezes until the path times out.

**Result**: run, 2026-09-16, passed. Before: a selection and an abandonment every 60 seconds,
15.0 s apart, every time, and pings through the tunnel averaging 1 600 ms with a worst case of
14 980 ms while pings outside it in the same minutes averaged 27 ms. After: six hole-punch
attempts in two and a half minutes, the overlay path opened at each, no selection at all, and
pings averaging 75 ms with a worst case of 1 403 ms. Paths that fall silent for other reasons are
now abandoned in 3.0 s rather than 15.0 s. The full figures are in the Android client's
verification.

On the same Wi-Fi the session still moves off the relay to the local path and the round trip goes
from 39 ms to 6–9 ms: the rule refuses what a tunnel of this machine carries, and a peer's address
that is withheld is not carried.

## 26. The three commands answer three different questions

With every network this device holds, at least one up and one down, and at least one network
holding a peer:

```
.\peerfectly.exe status
.\peerfectly.exe peers
.\peerfectly.exe peers <network>
.\peerfectly.exe address
.\peerfectly.exe peers <a name this device does not hold>
```

**Expect** `status` to describe the networks — state, this device's name and addresses in each,
how many devices it holds, where its relay is — and no device's detail; `peers` to describe the
devices grouped by network; `address` to answer with an address a line; and the last to be
refused by name. **Expect** each entry to read as one thing: a value too long for a line
continues inside its block rather than looking like the next entry.

**Result**: run, 2026-09-16, passed. Five networks on the desktop, two up and three down.
`status` drew one block each; a withheld IPv4 wrapped onto a second line and stayed inside its
block, as did a revocation's reason and the relay line. No peer's name appeared in `status`.
`peers` grouped by network and said `no other device is in it yet` for the two that hold nobody
else. `peers prova-tel` narrowed to that one. `address` printed five lines. `peers cliente` was
refused with *this device holds no network called `cliente`* — the same words `up` already
uses.

**Found, and it is the shell's**: redirecting to a file under Windows PowerShell 5.1 corrupts
every non-ASCII character — the rule arrives as three replacement characters, and so do the em
dashes the report has always contained. PowerShell decodes a native program's output with the console code page, `CP850`
here, rather than UTF-8. The bytes the program writes are correct: the same command with
`[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()` writes a clean file, and to a
console the standard library writes UTF-16 and nothing is mangled at all. Recorded rather than
worked around.

---

## 27. Bounded parameters change nothing for a network already founded

With every network this device holds, after a build carrying `network-parameter-bounds` — which
makes the roster refuse a name suffix outside `*.internal` and a prefix that is not a `/64`
inside `fd00::/8`:

```
.\peerfectly.exe status
.\peerfectly.exe up <each network in turn>
Get-NetRoute -AddressFamily IPv6 | Where-Object { $_.DestinationPrefix -like "fd*" } | Select-Object DestinationPrefix, InterfaceIndex
Get-DnsClientNrptRule | Where-Object { $_.Namespace -like "*.internal" } | Select-Object Namespace, NameServers
```

**Expect** every network to load and come up with the suffix and prefix it was founded with, and
none to be reported unusable — the rule is new, but every network here already satisfies it.
**Expect** one route per network up, exactly the network's `/64` and never wider, beside this
device's own `/128`. **Expect** one NRPT rule per network up, claiming that network's suffix and
nothing above it.

**Result**: run, 2026-09-17, passed. All five networks — `alarm`, `casa`, `prova-pc`,
`prova-tel`, `prova-v4` — loaded and came up, each with its founded suffix (`alarm.internal`,
`casa.internal`, `pc.internal`, `prova-tel.internal`, `prova-v4.internal`) and its derived
prefix. No network was reported unusable, and no message about parameters appeared at all. The
routing table held exactly five prefix routes, every one a `/64`:
`fdb0:b8a9:bb27:376::/64`, `fdde:8336:1f1e:a07e::/64`, `fd4a:fe3b:862b:c127::/64`,
`fd6e:3aa9:c6c:30e8::/64`, `fdac:6ce7:c88d:5a68::/64`, each beside this device's `/128` on that
network's own adapter. The NRPT held five rules, `.alarm.internal`, `.casa.internal`,
`.pc.internal`, `.prova-tel.internal` and `.prova-v4.internal`, each pointing at that network's
own address; none claimed `.internal` itself. `prova-v4` still withheld `192.168.1.250` as
conflicting with the local subnet, so the IPv4 rule this change does not touch is unaffected.

**Not shown here**: a network founded *outside* the grammar being refused. None exists on either
machine, and one cannot be made any more — the roster refuses to build or decode it, which is
the point. That refusal is covered by the vector corpus and by the daemon's own tests, including
a log whose genesis this build refuses being reported as that network being unusable with the
reason.

---

## 28. A stricter roster loads every network that was already there

With every network this device holds, after a build carrying
`roster-admission-authority` — which refuses an operation whose author has no
authority in the state its own ancestors imply, refuses one naming a device that
is not there, and keeps 512 of the 4096 places for revocations:

```
.\peerfectlyd.exe
.\peerfectly.exe up <each network in turn>
.\peerfectly.exe status
```

**Expect** every network to load and come up unchanged: the same suffix, the same
address for this device, the same devices and revocations. **Expect** nothing
about refused operations or a roster that cannot be derived — every operation in
these logs was written by an admin, so the new rules have nothing to refuse.

**Result**: run, 2026-09-17, passed. All five — `alarm`, `casa`, `prova-pc`,
`prova-tel`, `prova-v4` — loaded and came up, each with the address it had before
(`fdb0:b8a9:bb27:376:4947:48c9:58ef:7d7f`, `fdde:8336:1f1e:a07e:dccd:ab52:3a9c:902c`,
`fd4a:fe3b:862b:c127:65d2:2ad5:ab68:3969`, `fd6e:3aa9:c6c:30e8:9403:4516:5ab1:eb18`,
`fdac:6ce7:c88d:5a68:bd48:ab8a:2d74:1703`) and the same roles. Nothing reported a
refusal. `prova-tel` still holds the revocation of `emulatore` that `telefono`
authored, with its reason and its clock reading, which is the case that matters
most: a real revocation by another device survives rules that now judge authority
before admitting anything.

**Checked more precisely than the screen can show.** Each network's log was
loaded by a build from before the change and by one after it, and the derived
state's fingerprint compared:

| network | operations | fingerprint, both builds |
|---|---|---|
| `alarm` | 1 | `1c2a9eca1dade6d2468df59637186b74ced03cadd75df61f581f3c88bbc6f847` |
| `casa` | 1 | `16c7e548d9afc95eb095662fb67b695a08f3cd8e0dc55b6a6b3ae873fb92964b` |
| `prova-pc` | 2 | `c58f1962af9e5cd1a3105ac563eff612a837dcfdfb507cfa2a79691479c7a9c3` |
| `prova-tel` | 4 | `ecf7f24ab57f073b2a6dab1acb002a68061fd77ff0da86b7262f0496d3e74126` |
| `prova-v4` | 2 | `d128a3db8db6b2486409e13f82c18f1da57f8718736beed40166eb7a6b556460` |

Identical in every case, with every operation still held and none refused. The
change alters what derivation decides in two ways — an author absent from its own
ancestors, and a removal nobody was entitled to make — and no network here
contains either.

**Noted, not this change's**: `prova-tel` reported `[tunnel] 1354 bytes is past
the link's 1280` during the run, and the phone was unreachable from the desktop
(`the peer could not be reached: timed out`) while its own interface was up. The
inbound firewall question recorded in the Android client's verification is
still open and is the likelier explanation.

---

## 29. A relay whose certificate is not pinned can never admit anybody

Found in verification, not by a test. With a network founded against a relay that presents a
certificate no public authority vouches for — a self-signed one on a bare IP is the ordinary case —
and the certificate **not** pinned:

```
.\peerfectly.exe status            # reads: relay https://<host> (no certificate pinned)
.\peerfectly.exe admit <payload>   # from a device waiting at that same relay
```

**Expect**, and this is the defect: the admitting side cannot reach the relay. Its endpoint pins a
certificate only where the network does — `crates/transport-iroh/src/enrolment.rs:216` adds
`ca_tls_config` under `if let Some(certificate) = state.params.relay_cert` — so with nothing pinned
it verifies against the system's roots, which refuse that certificate. The **joining** side has no
such problem: it accepts the relay on sight when ordinary verification fails, registers, and shows
its payload exactly as it should.

So the failure appears on the machine that is working. The joining device waits its full ten
minutes and reports a timeout; the admitting side gives no reason at all, because from where it
stands nothing happened.

**Result**: run, 2026-09-17, **failed as described**. A `casa` founded against
`https://203.0.113.10` without pinning could not admit a phone: the phone showed its payload,
`mynet admit` never reached it, and the join ended in a timeout with nothing said about a
certificate anywhere. Re-founding the same network against the same relay **with** the certificate
pinned made the same enrolment work first time.

**What this costs**: a person who declines the fingerprint at founding — a reasonable thing to do
when you cannot check it — gets a network that looks healthy, reports no fault, and can never
enrol a second device. Nothing in `status` says so.

**Not fixed here.** It predates this change and is not what this change is about. It is written
down so the next person does not spend an evening on it, as this one did.

---

## 30. A network is born attested, and says nothing about confirming it

On a desktop with no networks, against a relay whose certificate no public authority vouches for:

```
peerfectly found casa --relay https://<relay>
peerfectly status
```

**Expect** the certificate to be fetched without being asked for, its fingerprint shown, and
pinning to wait on a person. **Expect** two signatures — the founding operation and the network's
first snapshot. **Expect** `status` to say `certificate pinned` and to say **nothing** about a
roster that cannot be confirmed.

**Result**: run, 2026-09-18, passed. `casa` was founded with one command and no flag about the
certificate; the directory held `snapshot` and `snapshot_at` beside the log, and `status` reported
`certificate pinned` with no line about confirmation anywhere. The two signatures are the cost of
the attestation existing from the first moment, and were accepted as such.

---

## 31. An enrolment delivers the attestation, and the device names the network itself

From a phone with nothing, into the network of §30:

```
(on the phone) join — relay only, no name for the network
peerfectly admit <payload>
```

**Expect** the phone to ask for a relay and its own name and **nothing else**. **Expect** the
network to be kept under a name taken from its own suffix. **Expect** the joining device to hold
the same snapshot the admitting side holds.

**Result**: run, 2026-09-18, passed. The form offered no field for a name for the network; the
network landed under `casa`, derived from `casa.internal`, typed by nobody. The snapshot on the
phone was **byte for byte** the one on the desktop — 1458 bytes — and dated at the moment it
arrived, on the wall clock, so it survives the phone's process being killed.

---

## 32. Replacing a device keeps the name, and does not make the admin equivocate

With a device already answering to a name, enrolling a second one that proposes the same:

```
peerfectly admit <payload>          # answers `yes` to replacing
peerfectly status
```

**Expect** the admitting side to stop before signing and name the device holding that name **with
its short id**, because a name is not an identity. **Expect** replacing to revoke that device and
admit the new one under the name, as one act. **Expect** `status` to contain **no** equivocation,
and the new device to be a member.

**Result**: run, 2026-09-18, passed. The question named `4507-ea3b-9c74-3a09 phone` and said the
revocation could not be undone; answering `yes` left `2 devices, 1 revoked`, the revocation
carrying *"replaced by a device admitted under the name `phone`"*, and the new device
`b87c-86e1-f341-b046` a member.

**What this caught on its first run, and why the test above is worded as it is.** The revocation
and the admission were signed against the **same** heads, so neither was an ancestor of the other:
one author, two branches, which is what equivocation is. The roster voids what such an author
signs and exempts only revocations — so the destructive half stood and the constructive half did
not. The device holding the name was expelled and the device meant to replace it never became a
member, on a log that cannot be unsaid. That network had to be abandoned and founded again.

---

## 33. A device keeps one directory per network, without being asked to tidy up

After the replacement of §32, on the phone:

```
adb shell run-as <package> ls files/peerfectly/networks/
adb shell am force-stop <package>     # the recovery runs when the service starts
adb shell run-as <package> ls files/peerfectly/networks/
```

**Expect** one directory afterwards, under the name the person already knew the network by,
holding the **live** membership. **Expect** nothing reported as unusable and nothing for a person
to remove.

**Result**: run, 2026-09-18, passed. Before: `casa` — the membership just expelled — beside
`network`, the live one under a provisional name. After the service started: **`casa` alone**,
holding the live membership (`b87c-86e1-f341-b046`, its roster 2746 bytes against the dead one's
1861), with no red row and nothing to remove. `contacts.json` appeared shortly after, so the two
devices had spoken.

**What this caught.** Left alone, a replacement leaves the replaced device holding a membership it
cannot tell is dead — the expulsion was signed elsewhere — beside the live one under a name nobody
chose. The phone reported the dead one as unusable and asked a person to remove it: tidying up
after a machine, for a state the product never means to be in.

---

## 34. A desktop re-join keeps the network up, and the command line stops offering to raise it

The desktop half of a step in the Android client's verification, and the first run with the **phone as founder**:
a network founded on the phone, joined from this machine, and then joined again from this machine so
the membership was replaced.

**Expect** the network to be carrying traffic after the second join without anybody being asked, and
the command line to say so instead of printing `next: bring the tunnel up: peerfectly up` — which is what
it printed after the *first* join, correctly, because a first join inherits no choice.

**Result**: run, 2026-09-18, passed. The network `home`, founded on the phone. What the daemon's own
directory records, read afterwards and independent of anything a screen said:

| file | written at | what it shows |
|---|---|---|
| `identity` | 17:17:01.310 | the provisional directory's key, from the start of the join |
| `roster.log`, `snapshot` | 17:17:36.36 | the roster arrived |
| `network.json` | 17:17:36.595 | `settle` recorded the network under the name it took over |
| `choice` | 17:17:37.276 | **`up`** |
| `endpoints.json` | 17:18:37.166 | the network running, a minute later |

The directory was created whole by `settle` at 17:17, and a provisional directory has never been
brought up, so it can hold no choice of its own. `choice` reading `up` 0.7 s after `network.json`
and a **full minute before the first endpoint** is the inheritance and the raise that follows it —
not a person typing `mynet up`, which would have written `choice` after the network was already
alive, not before it had spoken to anyone.

**What rests on the person's word and not on this table.** That the command line printed the
carrying line rather than the instruction to raise the tunnel. The run was reported as working
throughout, and the state above is consistent with nothing else, but the terminal was not captured.
The branch itself is held by `what_a_join_says_about_the_tunnel_is_what_the_network_is` and the two
tests either side of it.

---

## 35. The destination check does not refuse legitimate traffic

The compatibility claim in `inbound-destination-check`, which was an assumption until it was run:
every packet a device legitimately sends another is already addressed to that device, so refusing
the rest costs nothing.

**Expect** ordinary traffic to flow in both directions with both networks up, and nothing new in
`recently:`.

**Result**: run, 2026-09-18, **passed**, desktop and phone, on the network `home` with both sides up
and the new build on each.

| direction | what was sent | result |
|---|---|---|
| desktop → phone | ICMPv6 echo to `fd21:…:5561:cadb:3ae5:516d` | 4 sent, 4 received, 0% loss, 6 ms average |
| phone → desktop | HTTP to `pc.home.internal:8000` from the phone's browser | the directory listing rendered |

Both directions exercise **both** tunnels, which is why two tests are enough for four checks: the
desktop's echo request was accepted by the phone's tunnel, and the phone's reply was accepted by the
desktop's. The phone's request travelled over a TCP session that ran to completion, so every segment
in it passed the desktop's destination check and every response passed the phone's. The name
resolving as well means the resolver's own traffic crossed it too.

**Read honestly.** A phone-to-desktop `ping6` returned 100% loss, and that is **not** this rule: the
desktop's firewall has no inbound ICMPv6 Echo Request rule among those enabled, and the adapters are
in the `Public` profile. The HTTP server, which has its own allow rule, answered the same phone over
the same tunnel a moment later. A ping is a test of the firewall, not of the overlay, and treating
that loss as a defect would have been a third wrong cause in two days.

**Not read.** The fault lists. The daemon runs elevated and the console driving this run was not, so
`mynet status` could not be called; the phone's list was not opened either. The traffic above is the
stronger signal — a destination check refusing legitimate packets stops the traffic, it does not
merely mention it — but *"nothing new appeared in `recently:`"* is not something this run observed,
and it is not claimed.

---

## Memory

Measured 2026-09-14 on the development machine, `peerfectlyd` release build, during the phone
verification of the Android client. Task Manager's *memory* column (the private working
set); the working set and private bytes from `Get-Process peerfectlyd`.

| state | private working set | working set | private bytes |
|---|---|---|---|
| three networks up (`alarm`, `prova-pc`, `prova-tel`), one peer each | 6.6 MB | 20.0 MB | 36.0 MB |
| every network down | 8.3 MB | — | — |
| `alarm` up again | 17.2 MB | 34 MB | 20.5 MB |

Rosters: `prova-pc` 2 operations, `prova-tel` 4. The working set follows what Windows trims
more than what the daemon holds, so the numbers say "tens of megabytes", not which state costs
more. A roster of hundreds of operations is the measurement still missing, and the one the
roster's cost per operation makes interesting.

---

## Recording results

Replace each `not run` with what happened, **including anything that failed or was
skipped, and why**. A step recorded as passing when it was not run converts an
open question into a false answer — which is exactly what the contaminated NAT
matrix did before the real measurement caught it.

A test in `tests/documentation.rs` asserts every result still reads `not run`. It
will fail the moment you fill one in. That is deliberate: updating it should be a
conscious act, not a side effect.

## 36. The signing key cannot be read out

`windows-key-custody`, and the claim the whole change rests on: the key is made inside the TPM and
never exists as a value anywhere else.

```powershell
# The key, as the person's own store lists it.
certutil -user -key -csp "Microsoft Platform Crypto Provider"

# And an attempt to take it.
certutil -user -exportPFX <the key's name>
```

**Expect** the key to be listed under a name identifying the network, and every attempt to export it
to be refused by CNG rather than by us. **Expect** no file under the network's directory to contain
private signing material: the identity file holds the public half and the key's name.

**Result**: not run.

## 37. The asking is the key's, not the program's

**The test for design decision D3, and the one that decides whether F-05 is actually closed.**

The threat is a process running as the person. It does not run `peerfectly.exe`, so a prompt `peerfectly.exe`
shows is a prompt it skips. What must hold is that the *key* refuses to be used without the person,
whoever is asking.

```powershell
# Sign with the key from something that is not peerfectly.exe and asks nothing.
$key = [System.Security.Cryptography.CngKey]::Open(
    "<the key's name>",
    [System.Security.Cryptography.CngProvider]::new("Microsoft Platform Crypto Provider"))
$ecdsa = [System.Security.Cryptography.ECDsaCng]::new($key)
$ecdsa.SignData([Text.Encoding]::UTF8.GetBytes("not an act anybody asked for"))
```

**Expect** Windows to prompt for the person before that signature is produced, with the prompt naming
the network. **If it signs silently, this change has not closed F-05** and the UI policy is not doing
what it is here to do — record that, and do not record the rest as passing.

**Result**: not run.

## 38. A declined prompt signs nothing

```powershell
peerfectly revoke <a device> --reason "verifica"
# Decline the prompt.
peerfectly peers
```

**Expect** the command to say *not signed* and not to report a failure, and the device to still be in
the roster — here and on the other machine. **Expect** the daemon to be holding nothing afterwards: a
second `peerfectly peers` a minute later must look the same.

**Result**: not run.

## 39. A machine that cannot protect a key is a member and not an admin

With the TPM disabled in firmware, or on a machine without one:

```powershell
peerfectly status
peerfectly found casa --name desktop --suffix home.internal
peerfectly join --relay <the relay>
```

**Expect** `status` to say this machine cannot be an admin, and why. **Expect** founding to be refused
naming the reason and saying the device can join as a member, with **nothing created** — no directory
under the networks folder afterwards. **Expect** the join to work, the network to carry traffic, and
the device to be an ordinary member.

**Result**: not run.

## 40. The whole act, end to end, and the migration

The founding, the admission and the revocation each through the two-step exchange, on a machine whose
key is in the TPM — and the re-founding the compatibility decision requires.

**Expect**, in order:

| what | expected |
|---|---|
| the daemon starting on the old `home` | refused, naming the unprotected key, and **nothing removed** |
| `peerfectly found` | **two** prompts — the network, then its first snapshot — and a network with both |
| declining the second | the network stands, with no snapshot, and the report says which half did not happen |
| the first attestation | present from the founding, with no prompt: the attestation key asks nobody |
| `peerfectly admit` | one prompt, and the other device holds the network |
| `peerfectly revoke` | one prompt, and the revocation on both machines |
| the prompt's words | naming the network; what `peerfectly.exe` prints above it names the act |

**Result**: run, 2026-09-20, **partly passed, and it found four defects the suite did not**. Every
one of them sat between two halves that were each tested alone.

| what | observed |
|---|---|
| the key is made in the TPM | **passed**. `certutil -user -key -csp "Microsoft Platform Crypto Provider"` lists `mynet.test1.signing`, ECDSA nistP256, under `…\Crypto\PCPKSP\…` |
| the key-creation prompt names the network | **passed**. *"mynet — test1"*, with the description this code sets |
| the report says where the key is | **passed**. `custody: KeyStore` |
| the founding asks twice | **not passed on this run** — defect 1 below. Asked once; the network was founded without a snapshot |
| the first attestation is present, unprompted | **passed**, twice. 208 bytes, from the founding, with nothing asked |
| a device joins | **passed**. The phone joined and holds the network |
| `mynet revoke` asks | **passed after the fixes**: twice — the revocation, then the snapshot the network was owed. Both landed: `roster.log` 1988 → 2335 bytes, `snapshot` 1564 bytes |

**Defect 1 — the command line could not read a snapshot.** A founding signs twice and the second
request carries a *snapshot body*, not an operation. The describer read only operations, so it read
nothing, told the daemon the act was unreadable, and the network was founded with no snapshot.
Nothing failed: the daemon's tests asserted the second request was issued and passed, and the
command line was never asked to describe one.

**Defect 2 — nothing asked for a snapshot an act left owed.** `attest_now` signs synchronously, so
with the key out of reach it could not sign at all: it recorded a fault and moved on. A line under
`recently:` where a requirement belongs.

**Defect 3 — the keys were chosen after the networks were loaded.** `Service::over` builds networks
with keyless defaults and `with_keys` came afterwards, by which time every identity whose key the
TPM holds had already failed. The daemon reported *"this device's identity will not open"* for a
network whose key was in the store the whole time, and it was not wrong — it had loaded it the only
way it knew how.

**Defect 4 — the `HRESULT` for a declined prompt was the wrong constant.** `-2_146_893_802` is
`NTE_BAD_KEYSET`, not `NTE_USER_CANCELLED`, so *no such key* was reported as *the person declined*
— which sent the diagnosis of defect 3 in the wrong direction for a while. The codes are written in
hex now, where they can be checked against the documentation by eye, and a test pins them.

**Still not run here**, and each needs a deliberate act rather than another founding: the two
prompts of a founding seen on a **fixed** binary, declining the second, and the old network's
refusal. §37 is the one that decides whether F-05 is closed at all, and it is untouched.

## 41. The service starts with the machine, with nobody logged in

`windows-service-install`, and the property the whole change rests on. Reboot **A**, and do not log
in. From **B**, or from a phone on the network:

```powershell
# On B, while nobody is logged in at A.
ping nas.peerfectly.internal
```

Then log in at **A** and read what happened while nobody was there:

```powershell
sc query peerfectly
peerfectly status
```

**Expect** the ping to answer. **Expect** `sc query peerfectly` to say `RUNNING`, and `peerfectly status` to
show the network up and its roster dated — read the attestation's timestamp rather than a screen,
because a network that came up and never attested looks identical until the window runs out.

**Result**: not run.

## 42. An ordinary console answers, with no elevation anywhere

The point of the change, and the one thing a person will notice immediately. Open a console **as an
ordinary user, not elevated**, on a machine where the service is running:

```powershell
peerfectly status
peerfectly peers
peerfectly address
```

**Expect** all three to answer. Before this change the channel carried the creator's integrity label
and an unelevated process could not even connect — reading state is not a privileged act, and it
should not need an elevated console.

**Result**: on 2026-09-23, **passed after two fixes**. All three answer from an ordinary console with
no elevation anywhere.

It failed first, and the two reasons are worth keeping. The descriptor was correct all along —
`D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019f;;;IU)S:AI(ML;;NW;;;LW)`, read off the live pipe, which is
`GA` and `GRGW` as Windows maps them for a pipe, with the label present. What refused was the
client's own check on **what answered**: it read the far process's token, and an ordinary account
may not open the token of a process running as the system. It reads the channel's **owner** now,
off the handle it already holds.

Underneath that, a worse one. The refusal was returned as `PermissionDenied`, and the command line
already translates that kind into *"the daemon is running as Administrator and this is not"* — so a
refusal that knew exactly what was wrong came out as a guess that was wrong, and three attempts went
looking in the wrong place. A precise cause must not be given a kind that something else explains
over the top of.

## 43. A second account sees that something is there, and may touch none of it

Two people on one machine. Found a network as **you**, then log in as a second account on the same
machine and, without elevation:

```powershell
peerfectly status
peerfectly up casa
peerfectly peers casa
```

**Expect** `status` to answer, to list **no** networks, and to say that one on this machine belongs
to somebody else — a count, without the label. **Expect** `up` and `peers` to be refused **naming
authorisation**, never naming the roster: the two refusals have different remedies, and a person who
cannot tell them apart goes to the wrong one.

Then, from an **elevated** console as the second account:

```powershell
peerfectly takeownership casa
peerfectly status
```

**Expect** it to succeed and the report to say the network **was taken** — a hand-over that looked
like ordinary ownership would make a deliberate act a quiet one.

**Result**: not run.

## 44. The state is the machine's, and only the machine's

```powershell
# What the directory actually carries, read back rather than assumed.
(Get-Acl "$env:ProgramData\peerfectly").Sddl

# And an ordinary process trying to read a network's identity.
Get-Content "$env:ProgramData\peerfectly\casa\identity"
```

Run the second line from an **unelevated** console, as a second account.

**Expect** the SDDL to be `D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)` or Windows' equivalent spelling of
it — protected, `SYSTEM` and Administrators, nobody else. **Expect** the read to be refused.

This is also the step that settles what §10.4 of the change could not settle in a test: DPAPI's
machine scope separates *who else* can unseal, which needs a second account or a second machine.

**Result**: not run.

## 45. A daemon refuses to run from somewhere anybody can write

```powershell
# From a build directory, which every ordinary account can write by construction.
.\target\release\peerfectlyd.exe

# And the same, told to anyway.
.\target\release\peerfectlyd.exe --allow-unsafe-location
```

**Expect** the first to refuse, naming **the directory** and **who** can write it — *«somebody can
write here»* leaves a person nothing to do. **Expect** the second to start **and warn**, and to warn
again on a second start: a warning that stops after the first is a warning that stops being read, on
exactly the machine where it still applies.

**Result**: not run.

## 46. A network from the old shape is refused, named, and left alone

Before this change the networks lived in `%LOCALAPPDATA%\peerfectly`, sealed to the person. If one is
still there, or after putting a copy back:

```powershell
dir "$env:LOCALAPPDATA\peerfectly"
peerfectly status
dir "$env:LOCALAPPDATA\peerfectly"
```

**Expect** `peerfectly status` to name what is there, say it is not used, and say that the network must be
founded or joined again. **Expect** the directory to be **byte for byte what it was**: nothing moved,
nothing re-sealed, nothing adopted. The material is sealed to one person and the daemon is no longer
that person; a migration that failed half way would leave a directory sealed two ways, which shows up
as a network that loads on some starts and not others.

**Result**: not run.

## 47. The service registers itself, and removes itself

```powershell
# Elevated.
.\target\release\peerfectlyd.exe install --allow-unsafe-location
sc qc peerfectly
sc start peerfectly
peerfectly status

.\target\release\peerfectlyd.exe uninstall
sc query peerfectly
dir "$env:ProgramData\peerfectly"
```

**Expect** `sc qc` to show `AUTO_START`, `LocalSystem`, and dependencies on `Tcpip` and `Dnscache`,
with the registered command line carrying `--service --allow-unsafe-location` — an install from a
build directory that dropped its own override would register a service that refuses to start, and
the person would find out at the next boot rather than now.

**Expect** `uninstall` to stop it, wait for it to stop, and remove it; `sc query` to say it does not
exist; and the networks under `%ProgramData%\peerfectly` to still be there. Removing the service is not
removing what it holds.

**Result**: not run.

## 48. The pinned driver still loads, now that its signature is checked too

The digest says *this is the file that was pinned*. It says nothing about whether the file was worth
pinning, so the daemon now asks Windows as well.

```powershell
peerfectlyd.exe
```

**Expect** the `driver:` line, as before. **If it refuses**, read which check failed: a refusal
naming the **signature** means Windows will not vouch for that file, and the thing to replace is the
driver — **not** the pin. Re-pinning cannot help and the refusal says so, because a person told
their digest is wrong will otherwise go and re-pin the very file being refused.

**Result**: not run.

## 49. The tray is the person's program now

```powershell
# Unelevated, in a desktop session.
peerfectly tray
```

Then bring a network up and down from another console and watch the icon.

**Expect** the icon to appear, to follow the network up and down within a couple of seconds, and
*Stop* to be in its menu. Run as a **second account that owns no network here**, **expect** *Stop* to
be **absent** rather than greyed out: an item a person can click and be refused teaches them the menu
is decoration, on the one surface where they cannot read why.

**Expect** `peerfectly status` to say how to start it. Nothing starts it any more, and somebody used to
the icon appearing by itself will read its absence as a fault.

*Superseded on 2026-09-26 by `tray-network-controls`:* the tray starts at login now and `status` no
longer names it. Steps 62–69 replace this one.

**Result**: not run.

## 50. The signing key is the machine's, and the person can still use it

The seam between the two accounts. From an **elevated** console, with the service running:

```powershell
peerfectly found casa --suffix casa.internal --relay <relay> --name desktop

# The key, as the machine's own store lists it — not the person's.
certutil -key -csp "Microsoft Platform Crypto Provider"
certutil -user -key -csp "Microsoft Platform Crypto Provider"
```

**Expect** the command line to say it is making a signing key, and CNG's own *protect this key*
prompt to appear **in your session**. Then **expect** the founding to ask for that key **twice** more
— once for the network's first operation, once for the snapshot it is owed — and to end with the
network founded and a snapshot present.

**A first run of this failed, and the failure is why the step reads as it does.** The daemon made the
key itself, and `NCryptFinalizeKey` came back `0x800706BE` — `RPC_S_CALL_FAILED` — because that call
is where the prompt appears and a service in Session 0 has no desktop to show it on. The same
founding through a foreground daemon worked, which is what established the cause. Making the key now
happens in the command line, through `NeedsKey` → `KeyMade`, the same shape the signature already
used.

**Expect** the key to be listed by the **machine** form of `certutil` and **not** by the `-user`
form. That is the whole of what changed here: the daemon makes the key as `LocalSystem` and
`peerfectly.exe` opens it as you, so a key in either account's own container is a key the other cannot
reach.

**Expect**, from an **unelevated** console, `peerfectly found` to fail at the signature rather than
silently. A machine key admits `SYSTEM` and administrators, which is the bar founding already had.

**Result**: not run.

## 51. A payload naming another relay is refused, and nothing is contacted

Needs a network with a relay, and a second relay address it does not use. On the joining device,
start a join at the **other** relay; on the admin, with the network's relay host watched:

```powershell
netstat -ano | findstr <other relay's IP>
peerfectly admit casa "<payload>"
netstat -ano | findstr <other relay's IP>
```

**Expect** the refusal to name both relays and end with *Nothing was contacted.* **Expect** no
connection to the other relay's address in either `netstat` — the message is what the code says;
the socket table is what it did. The firewall log serves too.

**Expect**, on a network founded with no relay, a refusal naming `peerfectly relay`.

**Result**: run, 2026-09-23, passed. The other relay was a second `iroh-relay` on the same host,
`https://203.0.113.10:8443`, with its own self-signed certificate; the phone waited there. The
admission into `casa` was refused naming both relays, and `netstat` showed no connection to `:8443`
before or after. The same payload into `prova-senza`, founded with no relay, was refused naming
`mynet relay`.

Setting up the second relay met one thing worth knowing: two `iroh-relay` on one host collide on the
metrics port (9090) before either relay port, with *Address in use* and nothing naming metrics in
the config. The second needs its own `metrics_bind_addr`.

## 52. A move from the command line

From the owner's console, with the network up:

```powershell
peerfectly relay <new relay>
peerfectly status
```

**Expect** the fingerprint prompt in the same words founding uses, then the key's prompt for the
change. **Expect** `status` to name the relay being left, the date it stops being used — seven days
from now — and to say to keep it running until then.

**Expect** `peerfectly relay <the relay it already uses>` refused with nothing changed, also when written
in capitals or with a trailing dot.

**Result**: run, 2026-09-23, passed after three fixes. `casa` moved from `https://203.0.113.10`
to `https://203.0.113.10:8443`, a second relay on the same host with its own certificate. The same
relay, in capitals and with a trailing dot, was refused with nothing changed.

- **From an ordinary console the signature failed with a bare `0x80090010`**, printed twice. The key
  is the machine's and only an administrator may use it — as §50 says — but nothing said so. It now
  says to use an elevated console, and every signing command prints a refusal once.
- **Two relays on one host would have lost everybody at the move's end.** TLS carries no port, and
  the per-host verifier took the first rule for the host, so the new relay would have been checked
  against the old one's pin. It now accepts a certificate any of that host's relays would.
- **Getting here destroyed the phone's membership of `casa`** — F-22, older than this change: §51's
  test join made a key under the name `casa`'s key had, and the keystore replaced it. Keys now have
  names of their own; the phone joined `casa` again before this step.

## 53. A phone switched off during the move follows it

Switch the phone off (or its network) **before** step 52, and back on a day later, inside the window.

**Expect** it to reach the others through the old relay, receive the change, and show the move on
the network's screen. Nothing is joined again.

**Result**: run, 2026-09-23, passed. The phone, on mobile data with `casa` off while the move was
signed, came back a few minutes later inside the window: it reached the desktop, received the change,
named the new relay, and showed the move with the relay being left and its end.

## 54. The tunnel stays up throughout a move

A long `ping -t` across the network through step 52, and again across the end of the transition.
To reach the end without waiting a week, `peerfectly relay <address> --now` on a second test network.

**Expect** no gap longer than a few seconds at either moment: only the transport is replaced, and the
tunnel, its address and its routes stay.

**Result**: not run.

## 55. At the end, the old relay can be switched off with nothing lost

After the end `status` gives, stop the old relay.

**Expect** every device that was on at least once during the window to reach the others through
the new relay, and `status` to say nothing about a move. **Expect** a device that was off for the
whole window to find nobody — the documented residual — and a join again to bring it back.

**Result**: partly run, 2026-09-28. The old relay (the :8443 instance) was stopped **before** the end,
while `casa` was still leaving it: the desktop and the phone both moved to the new relay and kept
reaching each other. That is the heart of this step, and done early rather than after the end. Still
to see after the end (2026-09-30 23:55): `status` saying nothing about a move. The device off for
the whole window was not tried.

## 56. A move from the phone

On an admin phone, the network's screen, *change this network's relay*.

**Expect** it to be absent on a network the phone is only a member of. **Expect** the certificate
screen to say it is moving the network, confirm with *move the relay*, and then the phone's lock.
**Expect** *move at once* to warn before anything is sent, and *keep the transition* to send nothing.
Back on the network's screen, **expect** the relay being left and until when.

**Result**: run, 2026-09-23, passed. Absent on a network the phone is a member of. On the network it
administers: the form sent nothing by itself; the certificate screen named the network being moved
and confirmed with *move the relay*, behind the phone's lock; the network's screen then showed the
move. *Move at once* warned before anything was sent, and *keep the transition* sent nothing.

## 57. A network's adapter keeps its GUID, and survives the daemon being killed

After a build carrying `overlay-service-exposure`, from an elevated console, with `casa` up:

```powershell
Get-NetAdapter -Name "peerfectly casa" | Format-List Name, InterfaceGuid
peerfectly down casa
peerfectly up casa
Get-NetAdapter -Name "peerfectly casa" | Format-List Name, InterfaceGuid
```

**Expect** the same `InterfaceGuid` both times, and a different one for any other network that is
up. Then kill the daemon with `casa` up (`Stop-Process -Name peerfectlyd -Force`), start the service
again, and **expect** `casa` to come back up: Wintun 0.14 removes an adapter with the process that
made it, so no orphan holds the GUID. If `casa` fails to come up here, that premise is wrong.

**Result**: run, 2026-09-24, passed.
- **The GUID held.** `mynet casa` showed `{CAE59B5E-12F1-8EC0-881B-D978DAEE7C31}` before and after a
  down and up — version 8 and variant `10`, as derived.
- **No orphan.** The daemon was killed with `casa` up (`Stop-Process -Name mynetd -Force`) and the
  service started again, and `casa` came back up with its adapter. So Wintun removed the adapter
  with the process, and nothing held the GUID.

## 58. A port exposed to a network is reached from it and from nothing else

Elevated, with `casa` up and a listener on the desktop:

```powershell
peerfectly expose casa tcp 8000
python -m http.server 8000
```

**Expect** the phone, on `casa`, to open `http://<desktop's casa address>:8000`. **Expect** another
device on the same Wi-Fi, opening `http://<desktop's LAN address>:8000`, to be refused. In
`wf.msc`, **expect** the rule `peerfectly casa tcp 8000` in group `peerfectly`, with the interface
`peerfectly casa` and the remote addresses `casa`'s `/64` and IPv4 range. Bring `casa` down and up and
**expect** the phone to reach the port again without anything being redone.

**Result**: run, 2026-09-24, passed — once a rule that was not ours was out of the way.
- **The rule was right.** `mynet expose casa tcp 8000` answered `casa  tcp 8000`. The rule read back
  with remote addresses `100.64.0.0/255.192.0.0,fdf9:cb19:66f5:2d57::/64` and interface
  `mynet casa`.
- **The first attempt looked like a failure and was not one.** With `casa` off, the phone on the
  Wi-Fi *reached* `192.168.1.9:8000`. The listener was `python -m http.server`, and Windows' prompt
  had long ago allowed `python.exe` inbound on every port.
- **With those rules disabled for the test:** the LAN address was refused, and the phone on `casa`
  reached `100.97.232.36:8000` through the tunnel. The Python rules were then re-enabled.

**Worth knowing, and written into DESIGN.md §6.2:** `expose` opens a port to one network; it does not
close what other rules on the machine already open. A program Windows' prompt allowed is reachable
from the LAN whatever mynet does.

## 59. Who may expose, and what is removed

**Expect** `peerfectly expose casa tcp 8000` from a console that is **not** elevated to be refused as an
administrator's act, with nothing written. **Expect** `peerfectly unexpose casa tcp 8000` to remove the
rule, and `peerfectly exposed` to list nothing. Expose a port to a throwaway network, `peerfectly forget` it,
and **expect** its rule gone. Restart the service and **expect** no rule for a network the machine
does not hold.

**Result**: run, 2026-09-24, passed — after a fix to founding on Windows.
- **The refusal.** Expose from a console that was not elevated was refused as an administrator's
  act, and nothing was written.
- **Unexpose.** `unexpose casa tcp 8000` removed the rule and answered `nothing is exposed.`
- **Forget.** `prova-exp` was founded, brought up, and exposed on TCP 9000, and its rule was listed.
  `mynet forget prova-exp` took the rule with it.
- **Restart.** Before and after a restart of the service, `mynet daemon (UDP)` was the only rule
  named `mynet*`.

**The first founding of `prova-exp` failed**, with *the key store holds no key under that name*. This
was a regression from F-22's fix: the service drew the key's name twice, and fresh names made those
two different. It was fixed and founding was repeated; see F-22 in `SECURITY-REMEDIATION`.

## 60. The daemon's own rule admits UDP and nothing else

Elevated, before: `Get-NetFirewallRule | Where-Object DisplayName -like "*peerfectlyd*"` shows the rules
Windows' prompt made. Then:

```powershell
.\target\release\peerfectlyd.exe install --allow-unsafe-location
```

**Expect** the install to name each rule it replaced and `peerfectly daemon (UDP)` to be the only
inbound rule for the program, UDP only. **Expect** `uninstall` to remove it.

**Result**: run, 2026-09-24, passed.
- **Before**, the rules Windows' prompt had made for `mynetd.exe` were two named `mynetd` for this
  build's path, and two named `mynetd.exe` for a copy of the daemon in a temporary directory.
- **After `uninstall` and `install`**, the two for this path were gone, and `mynet daemon (UDP)`
  was the only rule for `target\release\mynetd.exe`.
- **The two for the other path were left alone, as designed**: they are not this program's. They
  were then removed by hand, being allow-everything rules for a binary in a temporary directory.

## 61. The leftover test rules are gone

Remove, by hand, the ICMP echo rules left on the development machine by earlier tests (F-11,
correction 4). **Expect** a ping from another device on the Wi-Fi to the desktop's LAN address to go
unanswered.

**Result**: run, 2026-09-24, passed. Removed by hand were the hand-made test rules still on the
machine: ICMPv6 echo and a TCP port, for `prova-pc` and `prova-tel`, all on any interface. After
that, `mynet daemon (UDP)` was the only rule named `mynet*`. A ping from the phone on the same Wi-Fi
to the desktop's LAN address (`adb shell ping -c 3 192.168.1.9`) lost all three packets.

## 62. The tray's menu: one submenu per network, and an icon that follows them

Build, then, elevated, re-register so the service carries the new descriptor:

```powershell
cargo build --release -p programs
.\target\release\peerfectlyd.exe install --allow-unsafe-location
```

Then, unelevated, in a desktop session:

```powershell
.\target\release\peerfectly.exe tray
```

**Expect** a header such as `peerfectly — 1 of 2 on`, then one submenu per network of yours with a
coloured dot (green on, grey off, amber for a problem). Inside each: a check item *On*, then the
device's name and its addresses, greyed. Then *Start at login*, *Stop service…* (administrators
only), and *Quit peerfectly*. **Expect** the tray icon's dot to change colour as networks go on and off
from another console. With Windows in dark mode, **expect** the menu dark.

**Result**: run, 2026-09-26, passed: the header, one submenu per network with its dot, *On*, the name and addresses, and the icon following `up` and `down` from a console. *Stop service…* was absent from this unelevated tray; see 65.

## 63. One network turned on and off from the tray, with no elevation

From the tray started in 62, check and uncheck *On* in `casa`'s submenu.

**Expect** `casa` to come up and go down, `peerfectly status` in another console to agree within a
couple of seconds, and no elevation prompt at any point.

**Result**: run, 2026-09-26, passed: `casa` came up and went down from its submenu, `status` agreed, and no prompt was shown.

## 64. Quit turns off only this person's networks, and is remembered

With `casa` on, choose *Quit peerfectly*. Then, in a console:

```powershell
sc.exe query peerfectly
peerfectly status
```

**Expect** the tray to close, `casa` to be down, and the service `RUNNING`. Then, elevated:

```powershell
sc.exe stop peerfectly
sc.exe start peerfectly
```

**Expect** `casa` to still be down afterwards: quitting was recorded as the person's choice.

**Result**: run, 2026-09-26, passed: the tray closed, the service stayed `RUNNING`, `casa` was down, and it stayed down across `sc stop` and `sc start`.

## 65. Stopping the service asks for elevation

As an administrator, open the tray and choose *Stop service…*. Decline the prompt; then choose it
again and accept.

**Expect** Windows' elevation prompt before anything happens; declining to leave the service
running; accepting to stop it (`sc.exe query peerfectly` reads `STOPPED`). As an account that is not an
administrator, **expect** *Stop service…* to be absent.

**Result**: run, 2026-09-26, passed after a fix.
- **First run: *Stop service…* was never offered.** The tray runs unelevated, and an unelevated administrator's token holds the group as deny-only, so the report's `may_stop_the_daemon` was false for every tray. The report now also says `could_stop_the_daemon` — the caller's token is the filtered half of an elevated pair — and the tray offers stopping on either. The offer decides nothing: the stop is asked again by the elevated `mynet stop`.
- **After the fix**, the item was offered to the unelevated administrator; declining the prompt left the service `RUNNING`, and accepting it stopped it.

## 66. A stopped service is shown, and started without elevation

With the service stopped, the tray from 65 still open:

**Expect** the icon to show the stopped state, the header `peerfectly is stopped`, and *Start peerfectly*.
Choose it and **expect** the service to start with no elevation prompt and the networks to appear
within ten seconds. Stop the service again, close the tray, and run `peerfectly tray`: **expect** it to
start the service by itself.

Then, from a console that is **not** elevated:

```powershell
sc.exe stop peerfectly
sc.exe sdshow peerfectly
```

**Expect** the stop to be refused (`Access is denied`), and the descriptor to read
`D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)`.

**Result**: run, 2026-09-26, passed: the tray showed the stopped state and *Start mynet*, which started the service with no prompt; a tray opened with the service stopped started it; an unelevated `sc stop mynet` was refused; `sc sdshow mynet` read the descriptor of D4.

## 67. The tray starts at login, unless switched off

Sign out and back in.

**Expect** the tray to start. Uncheck *Start at login*, sign out and in again, and **expect** it not
to start; `peerfectly tray` still opens it, and the entry is not written back.

**Result**: run, 2026-09-26, passed: the tray started at login, the `Run` value pointed at this build's `mynet.exe`, and once *Start at login* was unchecked the value was gone, the tray did not start at the next login, and it was not written back.

## 68. The service's log records who asked, and nothing it must not

Turn `casa` on and off from the tray, and admit a device. Then, elevated:

```powershell
Get-Content "$env:ProgramData\peerfectly\logs\peerfectlyd.log" -Tail 30
```

**Expect** a line per act, with who asked, the act, the network and the outcome, and the service's
start. **Expect** no resolved name, no payload, no confirmation code and no full-length key or id
anywhere in it. Then, from a console that is **not** elevated:

```powershell
Get-Content "$env:ProgramData\peerfectly\logs\peerfectlyd.log"
```

**Expect** it to be refused.

**Result**: run, 2026-09-26, passed: the service's start and stop and each act on `casa`, with who asked (as the account's SID), the act, the network and the outcome; no resolved name, payload, code or full-length id; nothing from iroh. Reading the file from an unelevated console was refused.

## 69. A network's current problem is one line, on the desktop and on the phone

Cause a problem: on the relay's host, stop the relay for a minute, with `casa` up. Then:

```powershell
peerfectly status
```

**Expect** one line, `problem: [transport] …` or similar, under `casa`, no `recently:` list, and no
block about `peerfectly tray`. **Expect** the phone's `casa` screen to show the same problem as one line.
Start the relay again and, ten minutes after the last failure, **expect** the line gone from both.

**Result**: run, 2026-09-26, passed: with the phone in airplane mode for half a minute, `status` showed one `problem:` line under `casa` and no `recently:` list or tray block, and the phone's `casa` screen showed one line under *problema in corso*. More than ten minutes later both were gone.

## 70. An ordinary event does not make a network look wrong

With `casa` up on the desktop and the phone, put the phone in airplane mode for half a minute and
take it out again. Then:

```powershell
.\target\release\peerfectly.exe status
```

**Expect** the tray to stay green, `status` to show no `problem:` line under `casa`, and the log to
have the session ending as an `INFO` line with `event`. Then, with the phone off `casa`, ping its
IPv4 address from the desktop for a minute:

```powershell
ping -n 60 <the phone's address in casa>
```

**Expect** the tray still green, and the log to have **one** `no session for` line for it rather
than one per packet.

**Result**: run, 2026-09-26, passed: after the phone's half-minute in airplane mode the tray stayed green, `status` showed no problem line, and the session ending was an `INFO` event in the log; a minute of pings to the phone while it was off `casa` left the tray green and one `no session for` line in the log.

## 71. The server, read before it is replaced

*After `admission-relay-binding` §55 (2026-09-30).* On the VPS:

```sh
uname -m
docker --version
docker compose version
systemctl list-units --type=service | grep -i relay
ps aux | grep -i iroh-relay | grep -v grep
```

Then read the 443 instance's configuration file, whatever the listing above names, and compare it with `deploy/server/relay.toml`. **Expect** to decide each difference, not inherit it. Copy its certificate and key into `/etc/peerfectly/certs` as `deploy/server/README.md` says, and write down:

```sh
openssl x509 -in /etc/peerfectly/certs/relay.crt -noout -enddate -fingerprint -sha256
```

**Expect** the fingerprint to be the one `casa` pins.

**Result**: run, 2026-09-28.
- **The VPS:** Ubuntu 20.04.6 on x86_64, with 952 MB of memory and no swap, too little to build Rust. So the image was built on the desktop with Docker Desktop and moved with `docker save` and `docker load`, as the README's alternative says.
- **Docker:** it was not installed. `docker.io` 26.1.3 and `docker-compose-v2` 2.27.1 were installed from Ubuntu's own repositories.
- **The old relay:** not a service. It had been started by hand with `sudo` on 2026-09-11, running as root, from `/etc/iroh-relay.toml`.
- **Differences from `deploy/server/relay.toml`, all decided in its favour:**
  - metrics were on, at the default `0.0.0.0:9090` (the host firewall rejected it);
  - access and limits were left to the defaults;
  - HTTP was on 8080 and nothing was listening there.
- **The certificate:** `/var/lib/iroh-relay/relay-new.crt`, valid until 2036-09-06, SHA-256 `00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF`. Copied to `/etc/mynet/certs`.
- **The host firewall** already admitted 80 and 443. Published ports do not pass through `INPUT`; 8444/tcp was opened in Oracle's security list.
- **Worth knowing:** Ubuntu 20.04 is out of standard support.

## 72. The image holds no key

On the VPS, from the copied repository:

```sh
docker compose -f deploy/server/compose.yaml build
docker run --rm --entrypoint sh peerfectly-server -c "find / -xdev \( -name '*.crt' -o -name '*.key' -o -name '*.pem' \) 2>/dev/null | grep -v '^/etc/ssl\|^/usr/share'"
```

**Expect** the build to finish, and the search to list nothing.

**Result**: run, 2026-09-28, passed: the search listed nothing.

## 73. The containers replace the old relay, and `casa` does not notice

Stop and disable the old instances (the 443 service, and the hand-run 8443 one if it is still there). Then:

```sh
docker compose -f deploy/server/compose.yaml up -d
docker compose -f deploy/server/compose.yaml ps
sudo ss -tulpn | grep -E ':(80|443|8444|9090) '
docker inspect --format '{{.Config.User}} {{.HostConfig.CapDrop}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.SecurityOpt}}' $(docker compose -f deploy/server/compose.yaml ps -q)
```

**Expect**:
- both services running;
- only 80/tcp, 443/tcp, 443/udp and 8444/tcp held, and nothing on 9090;
- each container `10001 [ALL] true [no-new-privileges:true]`.

On the desktop, with no change made to any device:

```powershell
.\target\release\peerfectly.exe status
.\target\release\peerfectly.exe peers casa
```

**Expect** `casa` up with its relay, and the phone reachable. Where it was direct before (phone on the same Wi-Fi, or on mobile data with a path that punched through), **expect** it direct again within a minute: that is QUIC address discovery still seeing each device's own address through Docker's published ports.

**Result**: run, 2026-09-28, passed after a fix.
- **First start:** both containers restarted in a loop, with *permission denied* on `relay.key`. Compose said `user: "10001"`, so the process's group was the image user's system group, not 10001, and the key is `root:10001 0640`.
- **Why the desktop test missed it:** Docker Desktop mounts Windows directories with permissive modes.
- **The fix:**
  - `user: "10001:10001"` in `compose.yaml`;
  - a group with gid 10001 in the image;
  - `deployment.rs` now asserts both.
- **After the fix:**
  - both services were up;
  - 80, 443/tcp, 443/udp and 8444 were held by `docker-proxy`, and nothing listened on 9090;
  - each container ran `10001 [ALL] true [no-new-privileges:true]`;
  - `casa` was up on the desktop, with the phone reachable, and no device changed.

## 74. `casa` uses the rendezvous, verified by the relay's pin

From an elevated console:

```powershell
.\target\release\peerfectly.exe rendezvous https://203.0.113.10:8444 --network casa
.\target\release\peerfectly.exe status
```

**Expect** the change signed (with the prompt, as for a relay change), and `status` naming the rendezvous beside the relay. On the phone, once it holds the change, **expect** the same on `casa`'s screen. After a few minutes, on the VPS:

```sh
docker compose -f deploy/server/compose.yaml logs --tail 100
curl -sv http://203.0.113.10:8444/r/00 2>&1 | tail -3
```

**Expect**:
- the logs to name no node, key or address: the relay at `warn`, the rendezvous with its one start line;
- the plain `http://` request to get no answer (the connection closed).

**Result**: run, 2026-09-28, passed.
- **The change:** `mynet rendezvous https://203.0.113.10:8444 --network casa` was signed. `status` on the desktop named the rendezvous beside the pinned relay, with no problem line, and the phone's `casa` screen showed it too.
- **The logs:** the relay's were a few warnings about closed streams, with no identity or address; the rendezvous's was its one start line.
- **Plain HTTP to 8444:** curl got no HTTP response, only the bytes of a TLS alert, which curl reports as HTTP/0.9.
- **Use by the devices:** no discovery line in the desktop's log since the rendezvous was set, so no refused publish and no certificate failure. That is evidence by absence; the rendezvous logs no requests by design.

## 75. A reboot brings both back

```sh
sudo reboot
```

**Expect** both containers running again with nobody logged in (`docker compose ps` after reconnecting), and `casa` reconnected on the desktop and the phone within a minute or two.

**Result**: run, 2026-09-28, passed: after `sudo reboot`, both containers were up again with nobody logged in, and `casa` reconnected on the desktop and the phone.

## 76. Times in `status` read as dates

```powershell
.\target\release\peerfectly.exe status
```

**Expect** every time as a local date and time to the minute with how far from now: the relay move's end as `until 2026-09-30 23:55 (in … )` while it lasts, the revoked phone's last contact and its revocation's clock as dates `(… days ago)`. **Expect** no count of seconds anywhere, such as `1790805300`.

**Result**: run, 2026-09-28, passed: every time in `status` read as a local date with how far from now — the relay move's end, the revoked phone's last contact and its revocation's clock — and no count of seconds appeared.

## 77. The tray lists each network's devices

Open the tray and `casa`'s submenu.

**Expect**, after *On*, the phone with a dot and how it is reached (`— direct` on the same Wi-Fi, `— via relay` on mobile data), and no address of this device. Put the phone in airplane mode: **expect** its line to turn grey and read `— not reachable` within a few seconds, with the menu not closing if it is open. Turn `casa` off from the tray: **expect** the phone listed by name only.

**Result**: run, 2026-09-28, passed: `casa`'s submenu listed the phone with how it was reached and none of this device's addresses; in airplane mode the phone's line turned grey and read `not reachable`; with `casa` off the phone was listed by name only.

## 78. The portable command line changes nothing on Windows

Before building `portable-cli`, save `peerfectly status`, `peerfectly peers casa`, `peerfectly address` and the usage (`peerfectly` alone, on standard error) to files. Build and restart the service, then run the same four again and compare with `Compare-Object`.

**Expect** no difference other than the relative part of the times. Then **expect** `peerfectly rendezvous https://203.0.113.10:8444 --network casa` refused as already set with nothing signed, and `peerfectly expose casa tcp 9999` followed by `peerfectly unexpose casa tcp 9999`, from an elevated console, to work as before.

**Result**: run, 2026-09-29, passed.
- **The four outputs:** `status`, `peers casa`, `address` and the usage after the build read as before: the same layout and lines, the usage in the same order with `mynet tray` last.
- **How they were compared:** by eye, not with `Compare-Object` against saved files. What stands behind that: during the change every string literal of the command line before and after was compared, and the only differences were the intended ones — the refusals of `NoCustody`, the device name read from `HOSTNAME` or `/etc/hostname` off Windows, and the tray's usage line moved into Windows' extras.
- **The rendezvous:** `mynet rendezvous https://203.0.113.10:8444 --network casa` was refused as already set, with nothing signed.
- **Expose:** `mynet expose casa tcp 9999` listed the rule, and `unexpose` left nothing exposed.

## 79. One batch per act, said before Windows asks

From `sign-in-one-batch`. Build with `cargo build --release -p programs`, then replace the service's `peerfectlyd.exe` and `peerfectly.exe` together, as for every change: the two speak one protocol and an old one does not understand the new answer.

Use networks made for this and nothing else, so `casa` is not touched. From an **elevated conhost** (the classic console, `conhost.exe`):

```powershell
.\target\release\peerfectly.exe found prova
```

**Expect**, in this order:

1. The key store's *protect this key* dialog. Its description now reads *peerfectly is asking to sign an administrative act for the network "prova". The window you asked from says which act. If you did not just ask for one, refuse.*
2. In the console, before anything else is asked: `prova: 2 acts to sign with this network's admin key`, then `1. found prova, with this device named …` with *this key signs every admin act for it from now on*, and `2. record prova's current membership (snapshot 1)` with *routine: … nobody's access changes*.
3. The line *Windows will now ask you to confirm. That confirmation is what signs the acts above; refuse it if they are not what you asked for.*
4. Then the key store's dialog, or dialogs.

Then:

```powershell
.\target\release\peerfectly.exe rendezvous https://example.invalid:8444 --network prova
```

**Expect** `prova: 1 act to sign`, then `change prova's settings to: no relay (its certificate not pinned), rendezvous example.invalid:8444, IPv4 range …`, with *every device in prova follows this*. Then the same line about Windows, and the dialog.

Repeat both commands from an **elevated Windows Terminal** with `prova2` in place of `prova`.

**Record**, for each of the four:

- **Dialogs:** how many appeared, one for the batch or one per act. Either is acceptable; the open question is which one this Windows does.
- **The act on the dialog:** whether it shows the summary line (`peerfectly · prova: found prova, …; record prova's current membership …`). If it does not, the console line before it is what says what the dialog is for.
- **Position:** whether the dialog opened in front of the console or behind it.
- **Refusing:** for one of them, refuse the dialog. **Expect** `not signed. Nothing changed.`, and `peerfectly status` showing nothing new.

Afterwards `peerfectly forget prova` and `peerfectly forget prova2`. Their keys stay in the machine's key store under `peerfectly.prova…`, unused.

**Result**: run, 2026-10-01, passed (reported by the person who ran it). Not reported: how many dialogs a batch produced, whether the dialog showed the summary line, and whether it opened in front of the console, in either console. Those stay open, and the console line before the dialog is what says what it is for whatever their answer.

## 80. Removing a network takes its key out of the machine's key store

From `forget-completely`. Build with `cargo build --release -p programs` and replace `peerfectlyd.exe` and `peerfectly.exe` together. From an elevated console, found a network made for this:

```powershell
.\target\release\peerfectly.exe found prova3
```

List the machine's keys and note the `peerfectly.prova3…` one, and `casa`'s:

```powershell
certutil -csp "Microsoft Platform Crypto Provider" -key
```

Remove it:

```powershell
.\target\release\peerfectly.exe forget prova3
```

**Expect**:
- the usual confirmation, answered `yes`;
- then, because this device is `prova3`'s only admin: *This device is the only admin of `prova3`. Once it is removed, nobody will be able to admit or revoke anything in it — a stolen device included.* and *Remove it anyway? [yes/no]*;
- answering `no` gives *nothing was removed.*, and `peerfectly status` still lists `prova3`;
- running it again and answering `yes` twice removes it from `peerfectly status`.

Then list the keys again. **Expect** no `peerfectly.prova3…` key, and `casa`'s key still there.

**Result**: run, 2026-10-01, passed (reported by the person who ran it).

## 81. The installer replaces the build-directory registration

From `installers`. `casa` up, the service registered from `target\release` with the override, as it has been. Note what is registered now:

```powershell
sc.exe qc peerfectly
```

Build the package. This takes a while the first time: it builds in `target\package-build`.

```powershell
.\deploy\windows\package.ps1
```

**Expect** `Built target\dist\peerfectly-0.1.0-windows-x64.msi`, then `UNSIGNED: …` as the last line.

Install it, keeping a log:

```powershell
msiexec /i target\dist\peerfectly-0.1.0-windows-x64.msi /l*v target\dist\install.log
```

**Expect** the notice page, one elevation prompt, and a last page with *Open peerfectly in the notification area* ticked. Finishing opens the tray. A package built on this machine carries no download mark, so SmartScreen does not appear here; it appears for a package downloaded from elsewhere.

From an elevated console:

```powershell
sc.exe qc peerfectly
Get-Service peerfectly
Get-Content C:\ProgramData\peerfectly\logs\peerfectlyd.log -Tail 20
```

**Expect**:
- `BINARY_PATH_NAME` reads `"C:\Program Files\peerfectly\peerfectlyd.exe" --service`, with no `--allow-unsafe-location`;
- the service is `Running`;
- the log since the install has no warning about where the daemon runs from.

From a **new**, non-elevated console:

```powershell
peerfectly status
sc.exe sdshow peerfectly
```

**Expect**:
- `peerfectly` found on the `PATH`, and `casa` up with its devices as before;
- the descriptor of step 66: `D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)`.

Also check that the Start menu has "peerfectly", and that it opens the tray **with no console window**. Then quit the tray from its menu and run:

```powershell
peerfectly tray
```

**Expect** the icon back, and the prompt back at once, with the console free.

**Result**: run, 2026-10-02, passed (reported by the person who ran it).

## 82. After a restart, the installed service brings `casa` back

```powershell
Restart-Computer
```

After logging in, from a new console:

```powershell
peerfectly status
```

**Expect** `casa` up, with nobody having started anything. The tray is there if it was set to start at login.

**Result**: run, 2026-10-02, passed (reported by the person who ran it).

## 83. An upgrade keeps the networks up

With `casa` up, build the package again and install it over the one that is there:

```powershell
.\deploy\windows\package.ps1
msiexec /i target\dist\peerfectly-0.1.0-windows-x64.msi
```

**Expect** the same pages, no error, and the tray offered again.

Then, from a new console:

```powershell
peerfectly status
Get-Item "C:\Program Files\peerfectly\peerfectlyd.exe" | Select-Object LastWriteTime
```

**Expect** `casa` up again with its devices, and the program's time that of this build.

**Result**: run, 2026-10-02, passed (reported by the person who ran it).

## 84. Uninstalling keeps the networks

```powershell
msiexec /x target\dist\peerfectly-0.1.0-windows-x64.msi
```

From an elevated console:

```powershell
Get-Service peerfectly
Test-Path "C:\Program Files\peerfectly"
[Environment]::GetEnvironmentVariable("Path", "Machine")
Get-ChildItem C:\ProgramData\peerfectly
```

**Expect**:
- `Get-Service` finds no service called `peerfectly`;
- `False` for the folder;
- a machine `Path` with no `peerfectly` in it;
- `C:\ProgramData\peerfectly` still there, with the networks in it.

The tray, if it was open, now shows the daemon stopped. Quit it.

**Result**: run, 2026-10-02, passed (reported by the person who ran it).

## 85. Installing again brings the networks back

```powershell
msiexec /i target\dist\peerfectly-0.1.0-windows-x64.msi
```

From a new console:

```powershell
peerfectly status
```

**Expect** `casa` back, up, with its devices.

To go back to running from the build directory instead, uninstall the package, then run this from an elevated console:

```powershell
.\target\release\peerfectlyd.exe install --allow-unsafe-location
```

**Result**: run, 2026-10-02, passed (reported by the person who ran it).

## 86. The old `mynet` installation is removed, with its keys

From `rename-to-peerfectly`. Run **with the old programs still installed**, before anything of
`peerfectly` is: once they are gone, nothing can name the keys they made.

From an elevated console, list the networks and forget each one, answering `yes`, and `yes` again
when asked about being the only admin:

```powershell
mynet status
mynet forget casa
```

Then check the machine's key store:

```powershell
certutil -csp "Microsoft Platform Crypto Provider" -key
```

**Expect** no key whose name begins with `mynet.`.

Uninstall the package from **Settings → Apps → mynet**. If the service was registered from a build
directory instead, run this from that directory:

```powershell
.\target\release\mynetd.exe uninstall
```

Then remove what an uninstall deliberately keeps:

```powershell
Remove-Item -Recurse -Force C:\ProgramData\mynet
Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name mynet
Remove-Item -Recurse HKCU:\Software\mynet
```

The last two are per person: run them as each person who used the tray.

**Expect**, at the end:
- `Get-Service mynet` finds nothing;
- `Get-NetAdapter | Where-Object Name -like 'mynet*'` lists nothing;
- `C:\ProgramData\mynet` does not exist.

**Result**: run, 2026-10-05, passed (reported by the person who ran it).

- **Keys were left behind, as this step expected they might be.** After `forget` and the uninstall, the key store still held several keys named `mynet.`. They came from networks founded and removed before `forget-completely` taught `forget` to delete a network's key. They were deleted with `certutil -csp "Microsoft Platform Crypto Provider" -delkey`, and the list then showed none.

## 87. A fresh install of `peerfectly`

Build and install, as in step 81:

```powershell
.\deploy\windows\package.ps1
msiexec /i target\dist\peerfectly-0.1.0-windows-x64.msi
```

From a new elevated console, found the network again:

```powershell
peerfectly found casa --relay https://<your relay>
peerfectly status
```

**Expect** the relay's certificate fetched and its fingerprint shown, with *Pin this certificate …? [yes/no]*: compare it with the one the relay host prints, then answer `yes`. Then:
- the service `peerfectly` running from `C:\Program Files\peerfectly`;
- `casa` founded and up;
- `certutil -csp "Microsoft Platform Crypto Provider" -key` listing a key beginning `peerfectly.casa.`;
- the Start menu entry "peerfectly" opening the tray with no console window.

**Result**: run, 2026-10-05, passed (reported by the person who ran it).

- `casa` was founded again with `peerfectly found casa --relay https://203.0.113.10`, pinning the same relay certificate after its fingerprint was confirmed. The phone then joined it (Android property 31).

## 88. Sessions on demand, with the phone

The PC and the phone updated together to the build of `on-demand-sessions`: the protocol changed
(`peerfectly/transport/2`), so one of each version cannot talk.

```powershell
.\deploy\windows\package.ps1
msiexec /i .\target\dist\peerfectly-0.1.0-windows-x64.msi
peerfectly status
peerfectly peers casa
```

Then, after eleven minutes with nothing carried to the phone:

```powershell
ping -n 4 <the phone's IPv4 address>
```

**Expect**:
- `casa` up, and `never attested` at most for the moments before this device attests;
- the phone reported reachable now by `peers`, with no session open beforehand;
- four replies to `ping`, the first one slower while the session opens again.

**Result**: run, 2026-10-07, passed (reported by the person who ran it).

## 89. The PC's name, renamed to one the phone can look up

This PC joined `casa` as `DESKTOP-RJUUBB3`, a name in upper case that the phone could not reach by.
On the package built from this change, from an elevated console:

```powershell
peerfectly status casa
peerfectly rename --id <this device's id> pc --network casa
```

Then, from the phone over wireless debugging: `ping` of the new and the old name, and a page served
on this PC's port 8000 (which `expose` opens) fetched by name with `nc`.

**Expect**: Windows Hello asked once; `status` naming this device `pc.casa.internal`; on the phone,
`pc.casa.internal` resolving to this PC and the old name no longer; the page fetched by name.

**Result**: run, 2026-10-09, passed.
- `status`: `this device pc.casa.internal [b477-30e2-0f86-8b53], admin`, and the rename waiting for
  `w2` only, switched off for four days: *"renaming of [b477-30e2-0f86-8b53] to pc"*.
- On the phone, a few seconds after the rename: `pc.casa.internal` resolved to `100.95.229.148` and
  `fd3e:487:33d9:4fb0:afa9:806c:121b:a7b4`, and `desktop-rjuubb3.casa.internal` was an unknown host.
  A first lookup made within seconds of signing still had the old name, as the phone had not yet
  received the rename.
- The page on port 8000 came back by name: `ciao da pc`, logged here from `100.102.49.135`, the
  phone's address in `casa`.
- `ping` from the phone to this PC got no answer, by name or by address, while this PC's `ping` to
  the phone got 3 of 3. Windows puts the `peerfectly casa` interface in the *Public* profile, and no
  rule there lets an echo request in. That is Windows' default and not the name: the page on port 8000
  is what reaches.
