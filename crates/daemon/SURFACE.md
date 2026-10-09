# What this crate offers, and what a binding must not

Two surfaces, and only one of them can be narrow.

This crate is a Rust library whose consumers include the suites that drive an
assembled node directly — which is how most of this daemon was built and how its
hardest defects were caught. Those suites legitimately reach parts of an act. A
surface narrow enough for a language binding would take that away and make the
tests worse.

So the narrowing happens twice. Here, the public list is written down and a test
holds it. Where a binding is built, the list below is what it must exclude.

## The public list

Twenty-three modules, in `lib.rs`, guarded by
`surface::the_public_surface_is_the_written_list`. A module that becomes public
without joining the list fails that test; a module on the list that stops being
declared fails it too.

Five modules are deliberately internal — `discovery`, `endpoints`, `names`,
`service` as a module, and whatever else no consumer names. `Service` itself is
re-exported, because it is the act; the module around it is not.

## Parts of an act a binding must not offer

Each of these is a form of an act that omits a step the whole act takes. Each
stays reachable because a suite needs it, and each is named for what it omits so
that nobody reaches one believing it is the other.

| part | omits | the whole act |
|---|---|---|
| `Node::admit_without_activating` | bringing the network up afterwards | `Service::admit` |

### Why this one exists at all

`Service::admit` admits an operation **and brings the network up if it is down**.
That second half is not a convenience: the requirement about administrative
actions says an act taken while the network is off must turn it on, visibly,
rather than sitting somewhere the person believes has taken effect.

`Node` does not know about tunnels. It admits to a roster and propagates, which
is the whole of its job, and ten tests across `assembled`, `membership` and
`propagation` drive exactly that — one of them a guard that scans for the
declaration. Routing them through `Service` would make them test the service
instead of the node, which is a worse test of what they are about.

It was called `admit_local` until this crate was extracted, and under that name
`Service::revoke` called it and skipped the activation for exactly as long as
nobody noticed. The name is the fix that survives a reader who is not looking for
the problem.

### The rule for a binding

Offer the whole act and never the part. A generated binding turns every public
item into a callable function in another language, where nobody reads the module
documentation on the way and the shortest name wins. `admit_without_activating`
must not be among them.

## What a renderer of the report owes

The report is data, and most of what it says about membership was written by a
device other than the one showing it. The command line meets the obligations
below in `control.rs`. Any other surface that draws a report — the Android client
first — owes the same, and nothing in the report's types can enforce it for them.

### Text written by other devices is seen, not obeyed

These fields carry strings exactly as another device signed them:

| field | written by |
|---|---|
| `Peer::name`, `Named::name` | whoever admitted or renamed the device |
| `Revocation::reason` | the admin that revoked |
| `Act::Renames(_, to)` | the device that signed the rename |
| `Network::relay`, `Network::rendezvous` | the founder, in the signed parameters |
| `Fault::cause` | this device, but it can quote any of the above |

A renderer must draw control characters, bidirectional formatting characters
(U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069), zero-width characters
(U+200B–U+200D, U+2060–U+2064, U+FEFF) and the line and paragraph separators
visibly instead of applying them. `control::shown` is the reference. An escape
sequence repaints a terminal, an override makes one name display as another, and
a zero-width space makes two different names look identical.

A lookalike letter is not caught by this. That is why the short id goes beside
every name.

### A name is never shown without its short id

`Named::id` and `Peer::id`. Two devices can share a name, and a revoked device's
name can belong to a current one. A row that shows a name and no id is a row on
which a person can revoke the wrong device.

### A name that cannot be looked up is said so

`Peer::name_resolves` is `false` for a device whose name is not a DNS label: one
admitted before names were held to the rule, with a space, an apostrophe or a dot
in it. Nobody reaches that device by name. A renderer says so beside the device,
and says that an admin fixes it with `rename`, rather than leaving a person to
find out from a browser that cannot find it.

### Times are claims unless they are this device's own

| field | whose clock | how to say it |
|---|---|---|
| `Revocation::signer_clock` | the revoking admin's | "the revoking device's clock said …", never "revoked at …" |
| `Waiting::signed_here` | this device's | "signed here at …" |
| `Contact::Recorded` | this device's | "last contact with this device …", never "last online" |
| `Branch` | — | has no time on purpose: both branches were signed by the accused |

`Signed::NotRecorded` means the operation carries no plausible time — every
operation signed before `membership-report` carries a counter there. Draw it as
no time, never as a date near 1970.

`Contact::NoneRecorded` means no contact is recorded on this device. Draw it as
that, never as "never": a device in contact before the record existed has none.

### A confirmation is a claim of holding, not of applying

A device absent from `Waiting::owed` said, in its own offer, that it holds the
operation. Nothing here shows that it applies it. Do not draw it as done,
enforced or in effect.

### A bound that is shown

`Network::waiting_unlisted` counts operations that were not listed. Revocations
are never among them. Say that there are more; never draw the list as complete.

### A network this device cannot confirm says so, and says which

`Network::confirmation` is `None` for a roster confirmed within the time the
network allows. Anything else means this device is **refusing sessions with peers
that are not administrators** of that network, in both directions.

| value | what it means | what a person does |
|---|---|---|
| `Stale` | the window passed with nothing fresher accepted | reach an administrator |
| `NeverAttested` | no snapshot has ever been accepted for it | reach an administrator |
| `ClockMoved` | this device's clock moved backwards | check the clock, then reach an administrator |

Draw all three, and draw them apart. A renderer that collapsed them into one flag
would leave the commonest — a network whose administrators have not signed
anything — reading the same as a clock that is wrong, and those have different
remedies. `Unconfirmed::remedy` is the reference wording.

**It must not read as a network that is merely quiet.** What a person sees when
their devices stop answering because this device will not talk to them, and what
they see when those devices are switched off, have to be different: the first has
something to do about it and the second does not. A count of peers that has gone
down, with nothing else said, is the failure this obligation exists to prevent.

`Network::peers` still lists every device the roster names, because the roster
still names them. Their reachability is what changes, and it changes for a reason
that is in this field and nowhere else in the report.
