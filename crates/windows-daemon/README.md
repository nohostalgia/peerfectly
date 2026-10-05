# windows-daemon

The node as a program on Windows: the packet device, the routes, the resolver,
the command line and the tray.

[`VERIFICATION.md`](VERIFICATION.md) is what a real machine has to show. This is
the reasoning.

## Two halves, and why the line is where it is

The crate is a **core** that builds anywhere and an **edge** that only builds on
Windows.

The core owns everything that is a *decision*: which routes should exist given
the signed parameters, what a name resolves to, which session a packet belongs
to, when to sync and publish and announce, the order bring-up happens in and what
is undone when a step fails. The edge — `platform/` — owns the calls that make
those real, and decides nothing.

The reason is not tidiness. A route plan computed by a pure function can be
tested exhaustively on any machine; `CreateIpForwardEntry2` can only be tested by
holding Administrator on Windows. Welding them together would leave the part most
worth testing — the part deciding whether a default route can ever be installed —
in the half nothing can reach.

The split is checked rather than claimed: **the core builds and passes on Linux
with the edge compiled out**, 123 of the 165 library tests.

## §2.6c is a property of the shape, not of a check

> With the network off, a device sends nothing to any infrastructure.

The first version of this daemon broke that, and the way it broke it is worth
recording. `assemble()` bound the transport at startup. Binding an endpoint is
not passive — it contacts the relay named in the signed parameters and starts
learning observed addresses. So the daemon would have been talking to
infrastructure while its owner believed the network was off.

The fix was not to add a check. It was to make the transport **not exist** while
the tunnel is down:

- `Gateway` holds no device until one is attached at bring-up.
- `Node` holds no transport until one is started at bring-up.
- Both are dropped by `down`, along with every open session.

A packet offered while down fails with `NotUp` because there is nowhere to put
it. Nothing reaches infrastructure because there is nothing to reach it *with*.
That is a stronger guarantee than a flag somebody has to remember to test, and
`connectivity.rs` carries a scan asserting the daemon binary never builds a
transport of its own.

## §13.7, decided: no idle timeout

The tunnel stays up until a person takes it down. `lifecycle.rs` contains no
timer, and a test asserts no shutdown path there mentions elapsed time — because
the easiest way for this to be reversed is somebody adding "just an idle timeout"
without knowing it was decided.

Automatic shutdown adds a second way for the network to stop working that the
person did not choose, and §2.6b builds the whole product around the first way
being *theirs*. The battery argument that motivates it on a phone is much weaker
on a plugged-in desktop. If a timer is ever added it should follow a measurement,
not precede one.

## A failed bring-up undoes itself

The interesting path is not the happy one. A route left behind after a failed
bring-up blackholes the network's prefix for the whole machine — worse than never
having tried, and invisible until somebody wonders why nothing works.

So the machine sits behind an interface (`machine.rs`) whose test implementation
can be told to fail at any step. Each step is undone in reverse when a later one
fails, every removal is attempted even after one fails, and whatever would not go
is **named** in the error. "The route was removed after the rule failed" is a
thing a test asserts here, not a thing a person checks by hand.

## Routes and the resolution rule fail differently

Routes are scoped to the adapter and die with it — including when the process is
killed. That is a property of Windows rather than of our shutdown path, which is
the only kind of cleanup guarantee worth relying on.

The NRPT rule is a registry value and dies with nothing. It survives a crash, a
kill and a power loss, and a stale one sends every name under the suffix to a
resolver that is not running — which looks to a person like the network being
broken rather than like a leftover.

So the rule carries a tag, and the daemon **sweeps on startup** as well as
removing on shutdown. Startup is the half that matters: the case that leaves a
rule behind is by definition the case where shutdown did not run.

## The resolver binds inside the tunnel

On the device's own overlay address, not `127.0.0.1`. Port 53 on loopback is
contested on a desktop, and losing that fight looks like name resolution being
broken. More importantly, binding inside the tunnel means the resolver **does not
exist while the tunnel is down** — the same property as above, obtained for free
instead of by remembering to stop something.

It forwards nothing. On Windows the NRPT rule scopes it to the suffix, so unlike
Android (§7.1) it never sees an unrelated query. A name under the suffix that
matches no device is answered as non-existent; a query from outside is *refused*,
so a rule letting the wrong things through shows up as a refusal rather than as
this daemon quietly resolving the internet.

## `unsafe`, eight times, and why the count is the wrong measure

The design began by saying `unsafe` would be confined to one module. That premise
was wrong eight times over, and each time the honest answer was the same.

| Module | Calls | Why no safe wrapper exists |
|---|---|---|
| `platform/route_table.rs` | 4 | IP Helper has none |
| `platform/driver.rs` | 3 | loading a library runs code from it, and asking whether Windows vouches for it has no wrapper |
| `platform/pump.rs` | 3 | a Win32 message loop, outside a windowing toolkit |
| `platform/custody.rs` | 14 | CNG has none, and the key must not leave the chip |
| `platform/protected.rs` | 11 | making a directory, or setting who may start the service, with a chosen access control has none |
| `platform/who.rs` | 19 | who is at each end of a pipe: `interprocess` gives the process id and stops |
| `platform/desktop.rs` | 5 | the tray's dark menus are an undocumented export found by ordinal, the elevation prompt is the shell's, and the tray's start-up messages need a message window |
| `programs/daemon.rs` | 1 | the service callback the control manager passes a raw argument vector |

Each carries its own `#[allow(unsafe_code, reason = ...)]`, and a scan asserts no
ninth place has any.

The last is the odd one, and it is listed rather than excused: **none of it is
hand-written.** `windows_service::define_windows_service!` generates a callback
the service control manager calls with a count and a pointer, and reading that
argument vector is the one block. The allowance sits on the macro invocation, in
a module that contains nothing else, so it cannot come to cover anything the
daemon does itself.

The fourth is the newest and the one worth reading twice. Every alternative to
calling CNG directly means the private key passing through something — a wrapper
that exports it, a helper that holds it — and the entire point of the module is
that it never does. There is no version of this with less `unsafe` and the same
guarantee.

Twice the alternative would have *lowered* the count while raising the surface.
Shelling out to `netsh` removes four FFI calls and replaces them with parsing
localized console output to learn whether a security-relevant operation
succeeded, plus a process spawned with Administrator rights. Pulling in `winit`
for the tray removes three and replaces them with a windowing toolkit and its
transitive tree, running elevated.

Counting `unsafe` blocks is a proxy for risk. Optimising the proxy at the expense
of the thing it stands for is how a codebase gets less safe while its metrics
improve.

## Which file loads matters more than which keyword marks it

`Wintun.dll` is a signed kernel driver, and this daemon runs as Administrator.
Anyone who can substitute that file gets code execution in an elevated process
and, through the driver, in the kernel. No amount of care with the `unsafe` block
addresses that. Two things do:

- **The path is absolute, from the executable's own location.** Loading by name
  uses the Windows DLL search order.
- **The digest is checked before the load.** `PINNED` starts empty and an empty
  list refuses everything, so the daemon fails closed and prints the digest it
  found, ready to paste.

What this does **not** defend against is somebody who can write the executable's
directory — they could replace the daemon as easily as the driver, and the
protection there is the directory's ACL. It catches the driver being swapped
while the binary is not, which is exactly the situation when the daemon runs from
a build or downloads directory. Which is how it runs during verification.

## The tray offers nothing consequential

It shows whether the network is on, and stops the daemon. No approving a device,
no revoking one, nothing signed. Those change who is in a person's network, and a
menu next to the clock — hit by accident, no confirmation, no context — is the
wrong place for them.

Everything it offers is also a command, so the daemon is usable over a session
with no desktop. That is how a person administers the machine that most needs
this software.

## Every command needs an elevated console today

Not by design. The daemon runs as Administrator, so the pipe it creates carries a
high integrity label, and Windows will not let a medium-integrity process write to
it — which is what connecting to a duplex pipe is.  from an ordinary
console gets access denied.

 says what a command *does*, which is still worth
distinguishing: reading state is not a privileged act and should not need
elevation. Today it does, because of how the daemon is deployed rather than what
the command is.

The fix is an explicit security descriptor on the pipe — a DACL limited to the
owning user, and an object label low enough that the same user at medium integrity
may write. It costs no new , and it belongs with the change that turns
this into a service running as , where the descriptor has to be answered
properly regardless.

## The command line says which answers are current

With the tunnel down the daemon reaches no infrastructure, so everything it knows
about other devices is old and it *cannot* refresh it without breaking §2.6c.
Rather than hide that, every answer is marked current or remembered, and a
remembered one carries when it was true.

It also says how many signed operations have reached nobody. That is the number a
person most needs and is least likely to ask for: an operation sitting in the
queue is a decision they believe they have already made. §2.6c's own consequences
call that the most dangerous failure in the system.

Commands that belong to enrolment are **absent**, not stubbed. A placeholder that
appears to work teaches a workflow that is not the one `enrollment-flow` will
give them.

## Several networks, and keys that belong to one

A device holds any number of networks. Each gets a directory under `networks/`,
named by a **label** the person chooses — `casa`, `lavoro` — and each gets **its
own keys**. Two networks holding the same physical device see two unrelated
devices, and nothing in either roster connects them.

That is not only about privacy, though the privacy is the point: two networks, or
two relay operators, could otherwise establish that they share a member from data
the protocol hands them. It also removes two collisions. The address prefix a
founder derives is seeded from its own device identity, so one identity per
machine would make two networks founded here derive the **same** prefix — a
guaranteed collision on the one machine that is in both. And a transport endpoint
is bound to the device's transport key, so one identity would present one node
identity at two relays.

**Unlinkability applies to networks acquired after this change.**
It does not apply to a network the device already had: a machine upgrading from
the single-network layout keeps
the identity it has, because regenerating it would make the machine a different
device in a network whose roster would load regardless — it would come up holding
a network it can no longer prove it belongs to, refusing every peer and refused by
all of them. So the network that was already there carries keys that were once
machine-wide. Nothing else does.

The cost is stated rather than hidden: **a revocation cannot cascade**. A
compromised device that is a member of three networks must be revoked in all
three, and nothing in the data can say the three memberships are the same
machine — which is the property being bought. The daemon knows which networks
*this* device holds, which is free and local; it keeps no record of whether a
device in one network is a device in another, because such a record on a stolen
machine hands over exactly the map the separation exists to deny.

## One act, one batch, one look before Windows asks

An act that signs more than once — founding (the network and its first
snapshot), replacing a device (the revocation and the admission built on it), any
act the network is then owed a snapshot after — is prepared whole by the daemon
and sent as one batch. `peerfectly.exe` checks that it is one act, lists every part of
it read off the bytes with what follows from it, says that Windows is about to
ask and what for, and signs the batch through one open key handle. The daemon
applies it whole or not at all.

The dialog is still CNG's, and its own policy still asks on every use. What
`peerfectly.exe` adds is what CNG accepts: a one-line summary of the batch as the
handle's *use context*, and the console as the dialog's owner window so it opens
in front. Whether this Windows shows the summary, and whether it asks once per
handle or once per signature, is recorded in `VERIFICATION.md` §79. `peerfectly.exe`
and `peerfectlyd.exe` speak one protocol: replace both together.

## This layer decides nothing the roster decides

No membership list, no cached authorisation, no roles. A packet, a session or a
name is served because the roster currently says so, never because the daemon
recorded that it did once — so a revocation takes effect without the daemon
having to notice. Scans assert the state is not there to hold.

## What the automated suite covers, and what it cannot

| Behaviour | Covered by |
|---|---|
| Route plan; never a default route | tests, any platform |
| What a name resolves to; the DNS wire format | tests, any platform |
| Bring-up order and rollback on failure | tests, via the `Machine` interface |
| Address→session routing; packet verdicts | tests, any platform |
| No transport or device while down | tests, any platform |
| Known vs last-known in every answer | tests, any platform |
| Roster replay from the operation log | tests, any platform |
| **Routes actually written and removed** | `VERIFICATION.md` only |
| **The adapter carrying real packets** | `VERIFICATION.md` only |
| **The NRPT rule scoping real queries** | `VERIFICATION.md` only |
| **Routes dying with a killed process** | `VERIFICATION.md` only |
| **Silence on the wire while down** | `VERIFICATION.md` only |
| **The tray responding** | `VERIFICATION.md` only |
| **Another user unable to open the pipe** | `VERIFICATION.md` only |
| **State unreadable by another user** | `VERIFICATION.md` only |

Everything in the lower half is **unverified until a person runs it**. It is
listed rather than implied, because an untested branch that looks tested is worse
than one that admits it.

## Three ways to find a peer, and the relay is the last

§2.9 orders the paths: the local network, then addresses cached from when it
was, then the rendezvous, then the relay. The relay alone would work — it
introduces two peers and iroh punches a direct path from there — but it needs the
internet and a server, and two machines in one room should not need either.

[`discovery.rs`](src/discovery.rs) runs what the relay does not provide.
**Announcing** puts this device's addresses on a multicast group every few
seconds, signed with its transport key, and immediately whenever they change —
the case that matters is a laptop moving from tethering to home Wi-Fi, half a
metre from its own server. **Listening** hears others do it, checks the
announcing key against the roster, and hands the addresses to the transport as a
hint. **Publishing** does the same through the rendezvous for peers that are not
on this network, and the cache is consulted before the rendezvous is asked.

Two properties hold this together. **Nothing here decides anything**: an address
is a hint, and a session opened over one is authorised from the signed roster
exactly like any other, so the worst a liar achieves is a dial that reaches
somebody who refuses it. And **all of it is a socket**, so all of it starts with
the tunnel and stops with it — §2.6c holds because nothing is left running, not
because a flag is checked.

The transport learns hints through two methods on the `Transport` trait that
default to doing nothing: `addresses` says where this node thinks it is, and
`learned` offers where a peer was seen. The in-memory implementations ignore
both, which is right for a transport that has no notion of an address.

## Installing it

**The package.** From the repository root, in PowerShell:

```powershell
.\deploy\windows\package.ps1
```

It builds `target\dist\peerfectly-<version>-windows-x64.msi` and adds its line to
`target\dist\SHA256SUMS`. It needs Rust, the .NET runtime 6 or later, and the
network, for WiX and Wintun. It builds in `target\package-build` and not in
`target\release`, because a daemon running from `target\release` holds its
executable open.

**Everything it fetches is checked.**
- WiX 5.0.2 and its two extensions come from NuGet, each against a SHA-256
  written in the script.
- Wintun comes from wintun.net. The archive and the DLL are checked against
  their SHA-256, and then **the daemon's own driver check** decides whether the
  DLL may be packed: `examples/check_driver.rs` calls the function the daemon
  runs before loading it, with its pins. So a package cannot carry a driver its
  own daemon would refuse, and there is no second list of digests to keep in
  step with `PINNED`. A test guards that the build keeps asking.

**Installing.** Double-click the `.msi`, or run `msiexec /i <file>`. It:
- installs for the machine, into `%ProgramFiles%\peerfectly`. Only the system and
  administrators can write there, so the daemon starts **without**
  `--allow-unsafe-location`;
- registers the service by running `peerfectlyd install`, the same registration as
  by hand, with the same rule about who may start and stop it. First it runs
  `peerfectlyd uninstall`, so a registration left over from a build directory is
  replaced and not kept;
- starts the service;
- puts the folder on the system `PATH`, so a new console has `peerfectly`;
- adds "peerfectly" to the Start menu, which opens the tray, `peerfectly-tray.exe`. The
  tray is a desktop program of its own and not a mode of `peerfectly.exe`: a console
  program gets a console window whenever it starts without one, and this one
  never does. `peerfectly tray` still works, and starts it and returns;
- offers to open the tray on its last page. The tray's first start adds the
  person's own entry to start it at login, as before.

**An unsigned package** — the default — makes SmartScreen say *Windows
protected your PC*. "More info", then "Run anyway", installs it. To sign:

```powershell
.\deploy\windows\package.ps1 -Sign <certificate thumbprint>
```

This signs `peerfectlyd.exe` and `peerfectly.exe` before they are packed, and the `.msi`
after, with a timestamp. It needs `signtool` from the Windows SDK, and a
code-signing certificate in the certificate store: a token or a provider's
cloud signing service appears there with its thumbprint. `wintun.dll` keeps
WireGuard LLC's signature, which the daemon checks. The build's last line says
`SIGNED:` or `UNSIGNED:`, so an unsigned package is never taken for a signed
one.

**Upgrading** is installing a newer package. The old one is removed first: the
service is stopped and unregistered, and the programs go. Then the new one is
installed, registered and started. The networks that were up come back up. The
same version installs over itself.

**Uninstalling**, from Settings → Apps or with `msiexec /x`, stops and removes
the service, the programs and the `PATH` entry. **It keeps
`%ProgramData%\peerfectly`**, which holds the networks, and their signing keys in the
machine's key store. A network is an identity, and removing programs is not a
decision about any of them. To remove a network and its keys, run
`peerfectly forget <network>` before uninstalling: that removal also asks whether
this machine is the network's only admin. Each person's entry starting the
tray at login is left behind, pointing at a program that is gone, and Windows
skips it silently.

## Deliberately elsewhere

| Deferred | To |
|---|---|
| A certificate to sign the installer and its programs with | a later change: `package.ps1 -Sign` is ready for it |
| `join`, `show-qr`, invite tokens, QR payload | `enrollment-flow` |
| The `127.0.0.1` web UI, its session token and `Origin` check | §7.3, whoever builds it |
| Reverse lookup, address → device | open; `tunnel` left it so |
| Equivocation across peers | `equivocation-detection` |
| The same daemon on Linux or macOS | not planned here |
