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
Nothing is signed for a member or for the network's only admin, and a founder can be demoted only
by itself: the roster's refusal is said, where before an act it gives no effect looked done. The
demoted device keeps its signing key until the demotion is settled — beneath the roster's base,
where nothing can void it — and then destroys it.

A member wanted as an admin is invited again with `invite --admin` and approved with `--replace`:
it gets a new id and address. A member keeps no key that could become an admin's, so promoting one
is not offered.

## The state directory can be chosen on Linux

`peerfectlyd --state <directory>` keeps the state there instead of `/var/lib/peerfectly`, for a
container that keeps one directory across restarts. A chosen directory is judged more strictly than
the default: absolute, no symbolic link on the way, every directory above it root's and writable by
nobody else, and its parent existing. The command line takes the keys directory from the daemon in
every request and judges it the same way.

## Updating

- **Admins first.** An admin's daemon from before this release admits new members as it always
  did, but cannot take a request from a device joining as an admin.
- **Members that joined before keep their key** and work as they did.
- **Going back a release after joining as a member is not possible:** the identity this release
  writes for a member is not readable by an older one.
- `peerfectly` and `peerfectlyd` speak one protocol: replace both together.
