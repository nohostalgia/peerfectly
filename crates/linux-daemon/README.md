# linux-daemon

The node as a program on Linux. `peerfectlyd` and `peerfectly` are built by the `programs` crate, which
hands over to this one on Linux:

```text
cargo build --release --locked -p programs
```

Every decision is the portable daemon's (`crates/daemon`). This crate calls the kernel, the TPM,
systemd-resolved and nftables, and decides nothing. A change that puts policy here has been made
wrongly even if it works.

## What each module does

| Module | What it does |
|---|---|
| `tun` | the packet device: a TUN interface that is never persistent, so it goes with the process |
| `netlink` | the link, its MTU, addresses (IPv6 with no duplicate detection) and routes |
| `ifname` | a network's interface name: `peerfectly` and ten hex digits of its adapter GUID |
| `resolved` | the network's suffix routed to its resolver on its own interface, with `resolvectl` |
| `firewall` | `table inet peerfectly`: new connections from a network refused unless exposed, drawn from `/var/lib/peerfectly/exposed.json` |
| `machine` | `daemon::Machine`, from the four above |
| `socket` | the control socket `/run/peerfectly/control.sock`, and the lock that makes this the only daemon |
| `who` | who is calling, from the kernel, and the person behind `sudo` from the process tree |
| `home` | `/var/lib/peerfectly`, root's and closed, and the check that the program runs from where only root writes |
| `custody` | signing keys: in the TPM behind a passphrase, or a file sealed with one |
| `log` | standard error, where systemd puts it in the journal |
| `quiet` | the TSS library kept off the terminal |
| `programs` | the two programs' bodies |

Pure logic compiles and is tested on every host, Windows included: names, argument lists, the
ruleset, who a caller is, the passphrase rules. What calls the kernel or the TPM compiles on Linux
only, and is tested in the testbed (`testbed/`, and `VERIFICATION.md`).

## `unsafe`

| Module | Calls | Why no safe wrapper exists |
|---|---|---|
| `tun.rs` | 2 | `TUNSETIFF` is an `ioctl` with an `ifreq`, and neither `libc` nor `rustix` wraps it |
| `quiet.rs` | 1 | setting `TSS2_LOG` needs `set_var`, `unsafe` in this edition; it is called before any thread exists |

Each carries its own `#[allow(unsafe_code, reason = ...)]`, and a test asserts that no third
module has any. Reading and writing packets, the socket's peer credentials, the terminal's echo and
the effective uid all go through `rustix` and `tokio`, with no `unsafe`.

## What it needs on the machine

| | Why | Without it |
|---|---|---|
| root, or `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE` | the TUN device, routes, the firewall, port 53 | nothing comes up |
| `/dev/net/tun` | the packet device | nothing comes up |
| `nft` in `/usr/sbin` or `/sbin` (nftables) | the firewall table | **no network comes up**: every service on the machine would be reachable from it |
| systemd-resolved in use | names under a network's suffix | networks carry traffic, and names do not resolve; `peerfectly status` says so |
| `libtss2-esys` and `libtss2-tctildr` | the programs link them | the programs do not start |
| a TPM 2.0 at `/dev/tpmrm0` | signing keys held by the chip | keys are files sealed with a passphrase |

"systemd-resolved in use" means the service is running **and** `/etc/resolv.conf` points into
`/run/systemd/resolve` or names `127.0.0.53`. With resolved running and `resolv.conf` written by
something else, glibc never asks it.

On Debian and Ubuntu:

```text
sudo apt-get install libtss2-esys-3.0.2-0t64 libtss2-tctildr0t64 nftables
```

On Debian 12 the package names end in `-0` and `0` instead of `t64`.

## Running it

`deploy/linux/peerfectlyd.service` is the systemd unit, with the reason for each setting beside it. It
keeps two capabilities and nothing else. The programs belong somewhere only root can write, such
as `/usr/local/bin`: the daemon refuses to start otherwise, and `--allow-unsafe-location` is for a
build directory, warned every time.

## Installing it

**The archive.** From the repository, anywhere Docker runs:

```text
deploy/linux/package.sh
```

It builds `target/dist/peerfectly-<version>-linux-x86_64.tar.gz` in a container, on the testbed's own
base, and adds its line to `target/dist/SHA256SUMS`. Inside the archive are `peerfectlyd`, `peerfectly`, the
unit, `install.sh` and their digests.

**Installing.** On the server, compare the archive's digest with that line before unpacking:
the script is about to run as root. Then:

```text
sha256sum peerfectly-0.2.0-linux-x86_64.tar.gz
tar xzf peerfectly-0.2.0-linux-x86_64.tar.gz
sudo ./peerfectly-0.2.0-linux-x86_64/install.sh
```

The script **checks everything before it writes anything**, and reports every missing piece at once
rather than the first:
- root;
- systemd;
- the architecture;
- each library the programs link, through `ldd`, with the package that provides it on
  Debian/Ubuntu and on Fedora, and an `apt-get` or `dnf` line to install them;
- the C library;
- `nft`;
- `/dev/net/tun`.

Where the machine has a TPM, it also checks the TSS's device plugin, `libtss2-tcti-device.so.0`. The
TSS loads it only when asked, so `ldd` never shows it, and without it a machine with a TPM is
answered as having none: its keys would silently become passphrase-sealed files.

Once the checks pass, it installs the programs in `/usr/local/bin` and the unit in
`/etc/systemd/system`, then enables and starts the service and shows `peerfectly status`.

**Which systems.** The programs need **glibc 2.34 or later**: Debian 12, Ubuntu 22.04, RHEL 9 and
Fedora 35, and anything newer. The archive is x86_64 only. The build measures the floor from the
programs on every run, and the script names it when a machine is below it.

**Upgrading** is the same command from a newer archive. The service is restarted on the new
programs, and the networks that were up come back up.

**Uninstalling:**

```text
sudo ./peerfectly-0.2.0-linux-x86_64/install.sh --uninstall
```

It stops and disables the service and removes the unit and both programs. **It keeps
`/var/lib/peerfectly`**, and lists the networks in it. A network is an identity, and removing programs
is not a decision about any of them. To remove a network and its key, run `peerfectly forget <network>`
while peerfectly is still installed: that removal also asks whether this machine is the network's only
admin. Deleting `/var/lib/peerfectly` by hand removes every network at once, without that question.

## Who may do what

- **Anybody** may connect and ask for `status`; what they are shown is what is theirs.
- **The owner of a network** brings it up and down with no `sudo`.
- **Acts that sign** — founding, joining, admitting, revoking, changing settings — need the
  network's key, which only root can reach, so they run with `sudo`, and ask for the passphrase.
  **Once per act**: everything an act signs — a revocation and the admission replacing it, an act
  and the snapshot the network is then owed — arrives as one batch, is listed with what each part
  does and what follows from it, and is signed with one entry of the passphrase. The prompt names
  the network and where its key is (`Passphrase for casa (TPM):`), and an empty entry refuses
  without costing the TPM a guess. Founding asks only to choose the passphrase and type it again;
  joining asks for it a third time when the proof of possession is due, after the wait.
  `peerfectly` and `peerfectlyd` speak one protocol: replace both together.
  Under `sudo` the act is the person's who typed it, so a network founded with
  `sudo peerfectly found` belongs to them.
- **Exposing a port and stopping the daemon** are acts on the machine, so they need `sudo`.

## What each custody defends against

| | Somebody with the key file | Root on this machine, at the time | A backup, a disk |
|---|---|---|---|
| TPM, behind a passphrase | nothing: it loads on this TPM only | can read the passphrase as it is typed, and then use the key here — never take it away | nothing |
| file sealed with a passphrase | as many guesses as their hardware allows | can read the passphrase as it is typed | as many guesses as their hardware allows |

The passphrase is never passed as an argument or through the environment, and never crosses to the
TPM in clear: every use is authorised through a salted HMAC session.

Removing a network (`peerfectly forget`) deletes its key file from `/var/lib/peerfectly/keys` along with its
directory, whichever kind it is. That matters most for a sealed file, which is the signing key
behind nothing but its passphrase. Deleting unlinks the file and reaches nothing else: **a copy
taken before — a backup, an image of the disk — still holds a sealed key**, and its passphrase is
still all that protects it.

The transport and attestation keys are `0600` files in `/var/lib/peerfectly`, as `identity`'s Unix row
says. They must work with nobody present, and root, a backup or a disk can read them. What they
allow is bounded: carrying traffic as this device, and dating a roster.

## Other firewalls

The daemon's table touches nothing outside itself. When `ufw` or `firewalld` also filters the
interface, what they refuse stays refused: a port exposed with `peerfectly expose` may still need their
permission. `firewalld`, for example:

```text
sudo firewall-cmd --zone=trusted --add-interface=<the peerfectly interface>
```

`peerfectly exposed` shows only what peerfectly wrote.
