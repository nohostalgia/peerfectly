## A member keeps no signing key

A device joining a network as a member used to make its signing key as carefully as an admin's: in
the TPM or a file behind a passphrase on Linux, in the key store with a consent dialog on Windows,
in the keystore on a phone. A member signs with that key once, for the join's proof that it holds
it, and never again. So a device without a terminal or a person at it could not join, and a person
who was "only a member" chose a passphrase that protected nothing.

- **A member's join asks for nothing.** The key is made in memory, signs the proof, and is cleared
  before anything is written. The device keeps the public half, from which its id and address
  derive, and its status says it holds no signing key.
- **Joining as an admin is said on purpose:** `peerfectly join <invite> --admin`, or the switch on
  the phone's join screen, off by default. The invite must be one made with `invite --admin`.
- **A join asking for the other role is refused, and the invite stays open.** The admin's pending
  list shows the refused request; the joining device says which role the invite makes and goes on
  waiting, since anyone holding the invite could have said it.

## Demoting an admin

`peerfectly demote <device>`, and a demote action beside revoke in the app, make an admin a member.
Nothing is signed for a member or for the network's only admin; a refusal the roster gives is said,
where before an act it gives no effect looked done. The
demoted device keeps its signing key until the demotion is settled — beneath the roster's base,
where nothing can void it — and then destroys it.

A member wanted as an admin is invited again with `invite --admin` and approved with `--replace`:
it gets a new id and address. A member keeps no key that could become an admin's, so promoting one
is not offered.

## The founder is 12 words, not a device

**Every network is founded again, and every board takes new firmware.** The roster's format is
`roster/v2`: an operation or a root of the earlier format is refused as a bad signature. Nothing
converts a network; found it again, and keep the words.

- **Founding shows 12 words**, the founder's key, once. Three of them, chosen at random, are typed
  back before anything is made; then the terminal and its scrollback are cleared. They are kept by
  the person and by no device: nothing writes them anywhere. Whoever holds them controls the
  network's admins, and lost words cannot be recovered — the network keeps working with its admins,
  but no admin can be added or removed again.
- **The words are typed on one line**, separated by spaces, each in full or by its first four
  letters; shown as typed, then cleared. 24 words are read too. Nothing turns a terminal's echo off
  any more, and one left off by an interrupted prompt is turned back on.
- **Only the founder's words act on an admin.** Admitting, demoting, revoking, renaming or setting an
  admin takes `--founder` (or the words in the app); an admin's key governs members. Two admins can
  no longer remove each other, which could let a stolen admin stay one. A demoted or revoked admin
  destroys its signing key at once.
- **A stolen admin's acts are undone in one act**: `revoke <admin> <reason> --founder` asks from which
  of its acts to void them; what it admitted leaves, what it revoked comes back, by itself, and is
  listed first: any of those can be revoked again, for good, in the same act.
- **The words sign any admin's act**, from any device holding the network, a member or one the
  network revoked: `--founder` on `revoke`, `demote`, `approve`, `invite`, `rename`, the relay and the
  anchors, and in the app. The founder's root follows, so light members follow too. Do it on one
  device at a time: the same words used on two at once cancel each other out, revocations apart.
- **`peerfectly recover <network> [--revoke <admin>]...`** makes this device the network's admin
  under a new identity, revoking up to two admins, when it is the only device left to trust. A
  device the network revoked reaches a member through a founder session, opened with a key the
  words make, which carries the roster and nothing else.
- **`peerfectly founder replace <network>`** changes the words: the new ones are shown and checked,
  the old ones sign the change.
- **`peerfectly history <network> [--by <device>|--by founder]`** lists who signed what, and whether
  it took effect, as far back as this device still holds; it needs no administrator.

## Joining is proved against what was held, and against the invite

- **A join never discards what the device held.** Joining a network this device already holds used
  to replace the old membership before anything was checked, and with it any revocation only this
  device had: a revoked admin's invite could undo its own revocation. The two are now merged and
  checked first; a join admitted by a device revoked here is refused, and the network held is kept.
  A replacement by an admin in good standing carries what this device held into the network.
- **Invites are version 3** (`peerfectly-invite-v3:`, in base32, as long as before). They carry the
  key of whoever issued them, and a device takes the network only with a root that key signed: the
  secret alone no longer lets anybody hand the device a network of their own making, which a network
  compacted past its founding could not disprove. An invite of an earlier version is refused with
  words saying to ask for a new one. A device approved through an invite takes the network from the
  device that issued it, and waits for it.
- **`peerfectly revoked`** names the founder for a revocation the founder signed.
- **A revoked device is told**: by a member it was talking to, when it next dials one, or at the end
  of the act where the founder's words revoke it. No timers: each is an event. `status` says
  "revoked by …", naming who; it invites nobody, and an admin destroys its signing key. Up, it runs
  with no tunnel and carries the roster alone, so that it comes back by itself if the founder voids
  the revocation. One that knows nobody left is refused by everybody, as before; invited back, its
  old keys are destroyed.
- **An invite from a device revoked here is refused before anything is sent**, and so is an invite
  into another network whose names would overlap one held: it says to forget the old one first.
  Invites now carry the network's suffix.

## The state directory can be chosen on Linux

`peerfectlyd --state <directory>` keeps the state there instead of `/var/lib/peerfectly`, for a
container that keeps one directory across restarts. A chosen directory is judged more strictly than
the default: absolute, no symbolic link on the way, every directory above it root's and writable by
nobody else, and its parent existing. The command line takes the keys directory from the daemon in
every request and judges it the same way.

## Dependencies

- `chrono`, unmaintained (RUSTSEC-2026-0543), is replaced by `jiff` for the dates the command line
  shows in the machine's time zone; they read as before.
- `url` 2.5.9, for a stack overflow in `Url::origin()` (RUSTSEC-2026-0592). Nothing here calls it.
- `redb` 5. A full member's base state on disk opens as before: none of its tables holds a type
  whose encoding 5.0 changed.

## Updating

- **Admins first.** An admin's daemon from before this release admits new members as it always
  did, but cannot take a request from a device joining as an admin.
- **Members that joined before keep their key** and work as they did.
- **Going back a release after joining as a member is not possible:** the identity this release
  writes for a member is not readable by an older one.
- `peerfectly` and `peerfectlyd` speak one protocol: replace both together.
