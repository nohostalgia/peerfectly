# Verification on Linux

What the automated suite cannot show, and the commands that show it.

**Run so far**: 37 of 37. Step 32's budget, not met for want of an iroh change, is met in step 35 on the project's fork of iroh; step 34 is iroh 1.3.0 unpatched, the figure the patch is measured against. Steps 1–17, 26 and 27 were run in the testbed, the interactive steps driven
through a pseudo-terminal; steps 18–25 were run by hand, with the Windows PC, the phone and WSL2,
and reported as passed. Step 28 was run in plain containers and one running systemd; step 29 was
run by hand on WSL2 and reported as passed. Steps 30 and 31, for the rename, were run by hand on WSL2 and reported as passed. Step 37, device
names and `rename`, was run in the testbed through a pseudo-terminal.

**On 2026-10-03 the product was renamed from `mynet` to `peerfectly`** (`rename-to-peerfectly`),
protocol included: nothing before that date speaks to anything after it. Commands and **Expect**
lines use the new names. **Result** lines keep the names they were taken with, because rewriting
them would be inventing an observation nobody made.

Two places, for two kinds of question:

- **The testbed** (part A), in Docker on the Windows machine: Linux daemons with their own packet
  devices, firewall tables and software TPMs. It answers what the kernel, the TPM and the command
  line do.
- **WSL2 with systemd** (part B): a Linux with a service manager, systemd-resolved and a boot. It
  answers what the testbed cannot, because a container has none of those.

Every command is PowerShell, run from the repository root, one per step:

```powershell
cd <the repository root>
```

---

# Part A — the testbed

Three nodes: `a` and `b`, each with a software TPM; `c`, with none. Each has two accounts:
`alice`, who may use `sudo`, and `bob`, who may not. Each container is its own network namespace,
so nothing here touches the Windows machine.

## 1. The nodes build and start

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml up -d --build
docker compose -f crates\linux-daemon\testbed\compose.yaml logs
```

**Expect**:
- on `a` and `b`, `the TPM can hold signing keys: they are made there`;
- on `c`, `no usable TPM: signing keys are files sealed with a passphrase`, with the reason `this machine has no TPM (/dev/tpmrm0 is not there)`;
- on all three, `the firewall table is in place`, then `running`;
- no line from the TSS library.

**Result**: run, 2026-09-30, passed.

## 2. The tests that need a kernel, a TPM and root pass

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml run --rm tests
```

**Expect** every test to pass, the `#[ignore]`d ones included:
- the TUN device appears and disappears with its descriptor;
- netlink leaves exactly the planned addresses and routes, with the IPv6 address never tentative;
- packets cross the device both ways;
- the firewall table is drawn from its record, survives being deleted, and leaves another table alone;
- the socket reads who is calling from the kernel, looks through a real `sudo`, and refuses an impostor;
- a second daemon is refused;
- a TPM key signs and verifies, a wrong passphrase is worded as wrong, repeated wrong ones reach the lockout, and the key does not load on a second TPM.
- a batch of three messages is signed from one authorisation, every signature verifying, and a wrong passphrase signs none of it;
- an empty entry at the passphrase prompt refuses without moving the TPM's dictionary-attack counter, where a wrong passphrase moves it.

The TSS library's own `ERROR` lines in this output come from the tests that provoke those errors on purpose. The programs silence the library; the tests do not.

**Result**: run, 2026-09-30, passed: 57 unit tests, and 14 ignored tests across `firewall`, `home`, `kernel`, `socket` and `tpm`. Run again on 2026-10-01 for `sign-in-one-batch`, passed: 61 unit tests and 16 ignored, the two new `tpm` tests among them.

## 3. Founding on `a`, in the TPM, through `sudo`

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a sudo -u alice sudo peerfectly found casa --name a
```

**Expect**:
1. *"Making the signing key for `casa` inside this machine's TPM…"*, then the passphrase asked twice, with nothing shown as you type.
2. `about to sign: found a network…`, and the passphrase asked.
3. `about to sign: record this network's state…`, and the passphrase asked again. Every use of the key is the TPM's to authorise.
4. `founded.`, with `signing key in this machine's key store`.

In the daemon's log (step 1's second command), **expect** every line of the act to read `who="1000"`, which is `alice`, not root.

**Result**: run, 2026-09-30, passed. It was driven through `script` with the passphrase piped in, so the prompts were not seen as a person sees them: step 15 is the interactive run.

## 4. The owner brings it up, without `sudo`

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a sudo -u alice peerfectly up casa
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a sudo -u alice peerfectly status
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a ip -br addr
```

**Expect**:
- `casa up (now)`;
- an interface `peer` followed by eleven hex digits, holding the device's IPv6 address as a `/128` and its IPv4 address as a `/32`;
- after the report, the line saying names will not resolve because `resolvectl` is not installed. The container has no systemd-resolved; part B covers it.

**Result**: run, 2026-09-30, passed.

## 5. The firewall table is as drawn

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a nft list table inet peerfectly
```

**Expect** three chains:
- `input`, with policy accept, jumping to `from_networks` only for `iifname "peer*"`;
- `from_networks`, admitting `established,related`, `meta l4proto { 1, 58 }` and port 53 to `fc00::/7`, then `jump exposed`, then `drop`;
- `exposed`, empty.

**Result**: run, 2026-09-30, passed.

## 6. The resolver answers on the overlay address

Take the address from step 4, and ask it for `a`'s name:

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a dig +short "@<a's overlay address>" a.casa.internal AAAA
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a dig +short "@<a's overlay address>" a.casa.internal A
```

**Expect** `a`'s IPv6 address, then its IPv4 address.

**Result**: run, 2026-09-30, passed.

## 7. Somebody who may not is told so, and nothing changes

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a sudo -u bob peerfectly stop
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a sudo -u bob peerfectly down casa
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a sudo -u bob peerfectly status
```

**Expect**:
- the first two to say *"… you are not authorised. Nothing was changed."* and to exit with an error;
- `status` to say *"one network on this machine belongs to somebody else"*, and to name nothing about it;
- `casa` still up.

**Result**: run, 2026-09-30, passed after a fix. The first run printed nothing and exited 0: the portable command line treated a refusal as a success on every platform. It now says so and fails, with a test.

## 8. Exposing needs `sudo`, and survives a restart

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a sudo -u alice peerfectly expose casa tcp 8000
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a sudo -u alice sudo peerfectly expose casa tcp 8000
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a nft list chain inet peerfectly exposed
docker compose -f crates\linux-daemon\testbed\compose.yaml restart a
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a sudo -u alice peerfectly exposed
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a nft list chain inet peerfectly exposed
```

**Expect**:
- the first `expose` refused, naming authorisation;
- the second to print `casa  tcp 8000`;
- two rules in `exposed`, one `ip6 saddr` and one `ip saddr`, both on `casa`'s interface and commented with the network's whole identifier;
- after the restart, `casa` up again by itself, and the same two rules.

**Result**: run, 2026-09-30, passed after a fix. The first run lost the rules on restart: the kernel's table was the only record, and a restart of the container's network namespace empties it, as a boot does. Exposures are now recorded in `/var/lib/mynet/exposed.json`, and the table is drawn from that record.

## 9. A second daemon does not start

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec c timeout 3 peerfectlyd
docker compose -f crates\linux-daemon\testbed\compose.yaml exec c peerfectly status
```

**Expect**:
- `not starting … another peerfectlyd is already running on this machine`, with an error exit;
- the running daemon still answering.

**Result**: run, 2026-09-30, passed after a fix. The first run started the second daemon: it removed the first one's socket and answered in its place. The lock was added for this.

## 10. A stop takes every network down first

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml stop a
docker compose -f crates\linux-daemon\testbed\compose.yaml logs a
docker compose -f crates\linux-daemon\testbed\compose.yaml start a
```

**Expect**:
- `stopping` and `stopped`, once each, as the last lines before the stop;
- after the start, `the networks left on are on again`.

**Result**: run, 2026-09-30, passed.

## 11. A machine without a TPM founds with a sealed file

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec c sudo -u alice sudo peerfectly found ufficio --name c
docker compose -f crates\linux-daemon\testbed\compose.yaml exec c sudo -u alice peerfectly status
docker compose -f crates\linux-daemon\testbed\compose.yaml exec c ls -l /var/lib/peerfectly/keys
```

**Expect**:
- the warning that the key will be a file sealed with the passphrase, and that the passphrase is the whole of the protection;
- a passphrase under twelve characters refused, with *"no key was made"*;
- a longer one accepted, and asked again for each signature;
- `signing key in a file sealed with a passphrase`;
- one `.sealed` file, `-rw-------`, root's.

**Result**: run, 2026-09-30, passed: the short passphrase was refused, the long one accepted, and the custody and file were as expected.

## 12. Without `sudo`, an act that signs is refused, and nothing changes

The owner asks, without `sudo`, for a change that must be signed:

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a sudo -u alice peerfectly rendezvous https://203.0.113.10:8444 --network casa
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a sudo -u alice peerfectly status
docker compose -f crates\linux-daemon\testbed\compose.yaml logs a
```

**Expect**:
- `about to sign: change the network's settings`, then *"this act signs with the network's key, which only root can reach: run it again with sudo. Nothing changed."*, with no passphrase asked and an error exit;
- `status` still showing `no rendezvous`;
- in the log, `needs a signature` followed by `not signed`, so that the daemon holds nothing waiting on the act.

**Result**: run, 2026-09-30, passed.

## 13. The unit file verifies

```powershell
docker run --rm -v "${PWD}\deploy\linux:/unit:ro" --entrypoint sh peerfectly-testbed-node -c "apt-get update -qq; apt-get install -y -qq systemd; install -m 0644 /unit/peerfectlyd.service /etc/systemd/system/; systemd-analyze verify /etc/systemd/system/peerfectlyd.service; systemd-analyze security --offline=true /etc/systemd/system/peerfectlyd.service | tail -1"
```

**Expect** nothing from `verify`, and an exposure of `OK` or better.

**Result**: run, 2026-09-30, passed: `4.0 OK`.

## 14. `b` joins a network founded on `a`, and the two reach each other

The network is `prova`, founded on `a` with the relay and its certificate pinned:

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a sudo -u alice sudo peerfectly found prova --name a --relay https://203.0.113.10 --fetch-relay-cert
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a sudo -u alice peerfectly up prova
```

Two PowerShell windows. In the first, on `b`:

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec b sudo -u alice sudo peerfectly join --relay https://203.0.113.10 --name b
```

In the second, on `a`, with what `b` printed:

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a sudo -u alice sudo peerfectly admit <what b printed>
```

**Expect**, in this order:
1. On `b`, `about to sign: prove that this device holds its own signing key`, and its passphrase asked. **Type it at once**: `a` is waiting on it, and the exchange has a deadline — left too long, `a` says *"the exchange took too long"* and both start again.
2. On `a`, six digits, and `waiting for that device`.
3. On `b`, the digits asked for: type what `a` shows.
4. On `a`, `Sign the admission?`, then its passphrase.
5. On `b`, `joined.`

Then, on `b`, without `sudo`:

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec b sudo -u alice peerfectly up prova
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a sudo -u alice peerfectly peers prova
docker compose -f crates\linux-daemon\testbed\compose.yaml exec b sudo -u alice peerfectly address prova
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a ping -6 -c 3 <b's address>
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a dig +short "@<a's overlay address>" b.prova.internal AAAA
```

`ping` by name will not work without systemd-resolved: part B covers names.

**Expect**:
- `up` to work for the person who joined, with no `sudo`;
- `peers` on `a` to show `b` reachable;
- replies to `ping`;
- `b`'s addresses from `a`'s resolver.

**Result**: run, 2026-09-30, passed after two fixes, both in the portable daemon and command line and so on Windows too.
- **The proof of possession could not be made from the command line.** The joining device is asked to sign it while it waits, and the wait asked the daemon without the wrapper that signs: it stopped with `unexpected answer from the daemon: NeedsSignature(…)`. The request also named no key (`key: ""`), so answering it would have had nothing to sign with. This was true since the signing key moved into the TPM on Windows (2026-09-20). Every join since had been the phone's, which is why nothing showed it.
- **A joined network had no owner.** The join path never recorded who it was for, which founding does. `b` was told `adopted`, then refused `up` on its own network.

Both have tests, and each test fails with its fix removed. After them, driven through a pseudo-terminal:
- `b` joined as described;
- `up` worked without `sudo`;
- `peers` on `a` showed `b` `reachable yes, direct`;
- `ping -6` got 3 of 3;
- `a`'s resolver answered `b.prova.internal` with `b`'s IPv6 and IPv4 addresses.

The relay's certificate fingerprint was `00:11:22:33…CC:DD:EE:FF`, the VPS's.

## 15. A person founds, admits and signs at a real terminal

Steps 3 and 14, typed by hand. **Expect**:
- every passphrase prompt to show nothing as it is typed;
- a wrong passphrase to say *"the passphrase is wrong; nothing was signed"*, with nothing changed, and no line from the TSS library.

For the wrong passphrase, on `a`:

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a sudo -u alice sudo peerfectly rendezvous https://203.0.113.10:8444 --network prova
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a sudo -u alice peerfectly status
```

**Result**: run, 2026-09-30, passed as far as a machine can see.
- A passphrase typed after its prompt never appeared in the terminal's recorded output, so echo was off.
- A wrong passphrase at a parameter change answered *"the passphrase is wrong; nothing was signed"*, with no TSS line, and `status` still showed `no rendezvous`.

What a person sees on the screen as they type was not observed by one.

## 16. The firewall between two peers

On `b`, a service listening on its overlay address, left running:

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec -d b nc -6 -lk 8000
```

From `a`, to `b`'s overlay IPv6 address:

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a nc -6 -z -w 3 <b's address> 8000
docker compose -f crates\linux-daemon\testbed\compose.yaml exec b sudo -u alice sudo peerfectly expose prova tcp 8000
docker compose -f crates\linux-daemon\testbed\compose.yaml exec a nc -6 -z -w 3 <b's address> 8000
```

**Expect** the first `nc` to fail and the second to succeed. `a` exposes nothing, so the second also shows the replies to a connection `a` opened arriving through `a`'s own table.

**Result**: run, 2026-09-30, passed: exit 1 before `expose`, exit 0 after.

## 17. `c` joins with a sealed key

As step 14, with `c` in place of `b`, and a passphrase of twelve characters or more.

**Expect**:
- `c`'s status to read `signing key in a file sealed with a passphrase`;
- one `.sealed` file, `-rw-------`, in `/var/lib/peerfectly/keys`;
- `c` to carry traffic like any member.

**Result**: run, 2026-09-30, passed:
- `c` joined and came up without `sudo`;
- the custody and the key file read as expected;
- `peers` on `c` showed `a` and `b` `reachable yes, direct`.

## 18. `b` joins the real `casa`, with the Windows PC and the phone

With `b` not yet in any network, admitted from the Windows PC:

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec b sudo -u alice sudo peerfectly join --relay https://203.0.113.10 --name linux-b
```

**Expect**:
- `peers` on `b` to list the PC and the phone;
- `ping -6` from `b` to each to reply;
- the PC's `peers` to list `linux-b`, reached directly or through the relay.

**Result**: run, 2026-10-01, passed (reported by the person who ran it).

---

# Part B — WSL2 with systemd

What a container cannot show: the unit, systemd-resolved, and a boot.

## 19. systemd is on in WSL2

In an Ubuntu WSL2 shell:

```bash
sudo sh -c 'printf "[boot]\nsystemd=true\n" >> /etc/wsl.conf'
```

Then, in PowerShell:

```powershell
wsl --shutdown
```

Open the Ubuntu shell again:

```bash
systemctl is-system-running
resolvectl status
```

**Expect** `running` (or `degraded`), and systemd-resolved answering.

**Result**: run, 2026-10-01, passed (reported by the person who ran it).

## 20. The programs are installed with their unit

In PowerShell, copy the binaries out of the testbed's image:

```powershell
docker create --name peerfectly-copy peerfectly-testbed-node
docker cp peerfectly-copy:/usr/local/bin/peerfectlyd .\peerfectlyd
docker cp peerfectly-copy:/usr/local/bin/peerfectly .\peerfectly
docker rm peerfectly-copy
```

In the WSL2 shell, from the repository root as seen there (`/mnt/c/<the repository root>`):

```bash
sudo apt-get install -y libtss2-esys-3.0.2-0t64 libtss2-tctildr0t64 nftables
sudo install -m 0755 peerfectlyd peerfectly /usr/local/bin/
sudo install -m 0644 deploy/linux/peerfectlyd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now peerfectlyd
journalctl -u peerfectlyd -n 20
```

**Expect** `the firewall table is in place` and `running` in the journal, with no timestamps of the daemon's own beside the journal's.

**Result**: run, 2026-10-01, passed (reported by the person who ran it).

## 21. Names resolve through systemd-resolved

```bash
sudo peerfectly found wsl --name w
peerfectly up wsl
resolvectl status
resolvectl query w.wsl.internal
```

`resolvectl status` should list the interface `peer…`.

**Expect**:
- that interface with the device's overlay address as its DNS server, `~wsl.internal` as its domain, and `Default Route: no`;
- `resolvectl query` answering with the overlay address;
- `resolvectl query example.com` still answered as before, and not by the network's resolver.

**Result**: run, 2026-10-01, passed (reported by the person who ran it).

## 22. A stop takes the network down; a kill leaves nothing

```bash
sudo systemctl stop peerfectlyd
ip -br link | grep peer
sudo systemctl start peerfectlyd
sudo systemctl kill -s KILL peerfectlyd
ip -br link | grep peer
resolvectl status | grep peer
```

**Expect** no `peer…` interface after the stop, none after the kill, and no resolver setting left behind. systemd restarts the daemon after the kill (`Restart=on-failure`), and the network comes back up.

**Result**: run, 2026-10-01, passed (reported by the person who ran it).

## 23. Without systemd-resolved, the tunnel still works

```bash
sudo systemctl stop systemd-resolved
peerfectly status
sudo systemctl start systemd-resolved
```

**Expect** the line saying names will not resolve because systemd-resolved is not running, and the network still up and carrying traffic.

**Result**: run, 2026-10-01, passed (reported by the person who ran it).

## 24. A boot brings it back

In PowerShell:

```powershell
wsl --shutdown
```

Open the Ubuntu shell again:

```bash
systemctl status peerfectlyd
peerfectly status
sudo nft list table inet peerfectly
```

**Expect** the daemon running with nobody having started it, `wsl` up, and the table in place with any exposure recorded before the shutdown.

**Result**: run, 2026-10-01, passed (reported by the person who ran it).

## 25. `/etc/resolv.conf` is untouched

```bash
sha256sum /etc/resolv.conf
peerfectly down wsl
peerfectly up wsl
sha256sum /etc/resolv.conf
```

**Expect** the two sums to be the same.

**Result**: run, 2026-10-01, passed (reported by the person who ran it).

---

# Part C — the testbed again, for `sign-in-one-batch`

## 26. One batch per act, one passphrase per batch

The nodes are rebuilt with the change and started fresh (`down -v`, then `up -d --build`). The network is `lotto`, founded on `a` in the TPM. Every command is run through `sudo` as in steps 3 and 14.

**Founding.** `peerfectly found lotto --name a` on `a`. **Expect**:
- the key's text saying the passphrase will be asked for every admin act this machine signs for `lotto` and that it cannot be recovered;
- *Choose a passphrase* and *Type it again*;
- `lotto: 2 acts to sign with this network's admin key`, listing `found lotto, with this device named `a` as its first admin` and `record lotto's current membership (snapshot 1)`, each with its consequence;
- *signing with the key you have just made, without asking again*;
- `founded.`, with **two** passphrase entries in all.

**Joining.** `b` joins as `laptop` (step 14's commands). **Expect**:
- on `b`: two entries to choose the passphrase, and one more for the proof, listed as `lotto: a proof to sign with this device's own signing key`;
- on `a`: one entry, after `lotto: 1 act to sign`, which shows `admit `laptop` (…) as a member` and *it will reach the devices in lotto, and they will reach it*.

**Replacing.** `c` (no TPM, so a sealed key) joins as `laptop` too, and `a` answers `yes` to *Replace it?*. **Expect** on `a`:
- one batch listing the revocation of `b`'s id, with the reason *replaced by a device admitted under the name `laptop`* and *permanent: …*;
- the admission of `laptop` after it, and a snapshot last if the network is owed one;
- **one** entry, with the prompt `Passphrase for lotto (TPM):`;
- `b` revoked and `c` a member.

**Revoking.** `peerfectly revoke laptop test --network lotto` on `a`. **Expect** one act listed as `revoke `laptop` (…): test` with *permanent*, and one entry.

**Changing settings.**
- `peerfectly rendezvous https://203.0.113.10:8444 --network lotto` on `a`. **Expect** `change lotto's settings to: no relay (its certificate not pinned), rendezvous https://203.0.113.10:8444, IPv4 range …` with *every device in lotto follows this*, and one entry.
- `peerfectly relay https://203.0.113.10 --network lotto`, confirming the fingerprint. **Expect** the relay and its pinned certificate's fingerprint in the list — the same fingerprint the confirmation showed — and one entry.

**Refusing.** At a revocation's prompt, press Enter on an empty line. **Expect** *not signed. Nothing changed.*, and the device still a member. The dictionary-attack counter is checked by the `tpm` test `an_empty_entry_refuses_without_costing_a_guess` in step 2.

**The network moving while a person decides.**
1. In one terminal on `a`, start a revocation and leave it at the passphrase prompt.
2. In a second terminal, change the rendezvous and complete it.
3. Answer the first.

**Expect** *the network changed while you were deciding … Nothing was applied; run the command again …*, and the device not revoked. Running the revocation again works.

**Record** the number of entries for each command, and the full text shown for the replacement and for the relay change.

**Result**: run, 2026-10-01, passed after one fix, driven through a pseudo-terminal.

**The fix: a join showed a placeholder.** On the joining device, the prompt read `Passphrase for network (TPM):` and the text before it named `network`. That is the label a join waits under before the network arrives. The text when the key was made also promised admin acts to a device joining as a member. The daemon now sends no name while a network is being joined, and every surface says *the network being joined*, with a member's text when the key is made. Both have tests, and the run below is after the fix.

Passphrase entries per command, against what was expected:

| Command | Entries | Expected |
|---|---|---|
| `found lotto` (TPM, relay pinned) | 2: choose and type again | 2 |
| `found solo` on `c` (sealed file) | 2 | 2 |
| `b` joins | 2 to choose, 1 for the proof | 2 + 1 |
| `a` admits `b` | 1 | 1 |
| `c` replaces `b` as `laptop` | 1 on `a`; `c` 2 + 1 | 1 |
| `revoke laptop test` | 1 | 1 |
| `rendezvous …` | 1 | 1 |
| `relay … --network solo` (sealed) | 1 | 1 |

What each showed:

- **Founding:** the key's text says the passphrase is asked for every admin act for `lotto` and cannot be recovered. Then `lotto: 2 acts to sign with this network's admin key`, with `found lotto, with this device named `a` as its first admin` and `record lotto's current membership (snapshot 1)`, and *signing with the key you have just made, without asking again*.
- **The replacement** on `a`, in full:

  ```text
  lotto: 2 acts to sign with this network's admin key

    1. revoke (07e9-74c1-da11-64af): replaced by a device admitted under the name `laptop`
       permanent: a revoked device never comes back under the same identity
    2. admit `laptop` (2e42-2b7e-a62d-7b74) as a member
       it will reach the devices in lotto, and they will reach it

  The signing key for `lotto` is in this machine's TPM, and your passphrase is what unlocks it. Nothing is signed without it. Press Enter on an empty line to refuse.

  Passphrase for lotto (TPM):
  ```

  No snapshot was in the batch: the network had been founded minutes earlier, so none was owed. Afterwards `b` was revoked and `c` was a member.
- **The relay change** on `c`, in full:

  ```text
  solo: 1 act to sign with this network's admin key

    1. change solo's settings to: relay https://203.0.113.10 (its certificate pinned as 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF), no rendezvous, IPv4 range 100.64.0.0/10
       every device in solo follows this

  The signing key for `solo` is in a file on this machine sealed with your passphrase, and the passphrase is what unlocks it. Nothing is signed without it. Press Enter on an empty line to refuse.

  Passphrase for solo (sealed file):
  ```

  The fingerprint is the one the pinning question had just shown.
- **Refusing:** an empty line at a revocation's prompt gave *not signed. Nothing changed.*, exit 1, and the devices were unchanged.
- **The network moving:** a revocation was left at its prompt, and a rendezvous change was completed in a second terminal. Answering the revocation then gave *the network changed while you were deciding … Nothing was applied; run the command again …*, and nothing was revoked. The message first said *another admin's change arrived*. Here the change came from this machine, so it now says *another change was signed here or arrived from another admin*. Run again, the revocation went through with one entry.

Seen and not part of this change:

- **A failed admission attempt.** One attempt stopped before anything was signed, with *the endpoint could not be bound: connection lost* while reaching the relay. The retry worked.
- **`b` and `c` show the roster as never confirmed.** Both were revoked during the step, so no admin attests to them.

## 27. Removing a network deletes its key file

From `forget-completely`. On fresh nodes:
- found `chiave` on `c`, which has no TPM, so its key is a sealed file;
- found `chiave` on `a`, where the key is TPM-wrapped;
- found a second network, `resta`, on `c`.

Then, on each:

```powershell
docker compose -f crates\linux-daemon\testbed\compose.yaml exec c ls /var/lib/peerfectly/keys
docker compose -f crates\linux-daemon\testbed\compose.yaml exec c sudo -u alice peerfectly forget chiave
docker compose -f crates\linux-daemon\testbed\compose.yaml exec c ls /var/lib/peerfectly/keys
```

**Expect**:
- the usual confirmation, then, since this device is `chiave`'s only admin, *This device is the only admin of `chiave`…* and *Remove it anyway? [yes/no]*;
- `no` gives *nothing was removed.*, and `chiave`'s `.sealed` file is still there;
- `yes` twice removes it: `chiave`'s `.sealed` file is gone from `/var/lib/peerfectly/keys`, `resta`'s is still there, and `status` lists only `resta`;
- the same on `a` with a `.tpm` file.

**Result**: run, 2026-10-01, passed, driven through a pseudo-terminal.

- **Before.** `c` held `mynet.chiave.12776e889cb4dbac.signing.sealed` and `mynet.resta.2fe53b8535e948d8.signing.sealed`; `a` held `mynet.chiave.fcd4c9670ff4dfd5.signing.tpm`.
- **`forget chiave` on `c`, answered `yes` then `no`.** The question read *This device is the only admin of `chiave`. Once it is removed, nobody will be able to admit or revoke anything in it — a stolen device included.* Answering `no` gave *nothing was removed.*, exit 1, and both files stayed.
- **The same, answered `yes` twice.** `chiave`'s `.sealed` file was gone, `resta`'s was still there, and `status` listed only `resta`.
- **On `a`, `yes` twice.** The `.tpm` file was gone, and the keys directory was empty.

# Part D — the archive and its install script, for `installers`

## 28. The install script refuses before it writes, and installs under systemd

Build the archive:

```powershell
& "C:\Program Files\Git\bin\sh.exe" deploy/linux/package.sh
```

Then run the script from it where something is missing:

```powershell
docker run --rm -v "${PWD}\target\dist:/d:ro" debian:bookworm-slim sh -c "cd /tmp && tar xzf /d/peerfectly-0.1.0-linux-x86_64.tar.gz && ./peerfectly-0.1.0-linux-x86_64/install.sh; echo rc=`$?; ls /usr/local/bin /etc/systemd/system | grep peerfectly"
docker run --rm -v "${PWD}\target\dist:/d:ro" debian:bullseye-slim sh -c "cd /tmp && tar xzf /d/peerfectly-0.1.0-linux-x86_64.tar.gz && ./peerfectly-0.1.0-linux-x86_64/install.sh"
docker run --rm --user 65534 -v "${PWD}\target\dist:/d:ro" debian:bookworm-slim sh -c "cd /tmp && tar xzf /d/peerfectly-0.1.0-linux-x86_64.tar.gz && ./peerfectly-0.1.0-linux-x86_64/install.sh"
docker run --rm -v "${PWD}\target\dist:/d:ro" ubuntu:24.04 sh -c "cd /tmp && tar xzf /d/peerfectly-0.1.0-linux-x86_64.tar.gz && ./peerfectly-0.1.0-linux-x86_64/install.sh | grep 'To install'"
```

**Expect**:
- in `bookworm-slim`: every missing piece in one list, not only the first. That is no systemd, the three TSS libraries each with its package, `nft` and `/dev/net/tun`. Then an `apt-get install` line using Debian 12's names, `rc=1`, and nothing named `peerfectly` in either directory;
- in `bullseye-slim`: the same, plus the C library named as older than glibc 2.34, with the releases that are new enough;
- as `nobody`: *this needs root: run it again with sudo* first in the list;
- in `ubuntu:24.04`: the `apt-get install` line with the `t64` names.

Then the whole path, in a container running systemd. The container is built from `debian:bookworm` with `systemd`, the three packages the script suggested and `nftables`, and run with `--privileged --cgroupns=host --device /dev/net/tun`:
- `install.sh`;
- `install.sh` again, which is the upgrade;
- `install.sh --uninstall`;
- `install.sh` again.

**Expect**:
- after the install: the service enabled and active, the programs `root:root 0755` in `/usr/local/bin`, `ExecStart` with no override, no location warning in the journal, and `peerfectly status` shown;
- the upgrade says it is one, and the daemon's process changes;
- the uninstall removes the unit and both programs, lists the networks under `/var/lib/peerfectly/networks`, and leaves them.

**Result**: run, 2026-10-02, passed.
- The refusals were as expected, in all four containers. `bookworm-slim` suggested `libtss2-esys-3.0.2-0 libtss2-tctildr0 libtss2-mu0 nftables`. `ubuntu:24.04` suggested `libtss2-esys-3.0.2-0t64 libtss2-tctildr0t64 libtss2-mu-4.0.1-0t64 nftables`. `ubuntu:22.04` was also tried, and got Debian 12's names. In each refusing container nothing was written.
- In the systemd container:
  - **Install.** `mynet 0.1.0 is installed`, then the status: no network yet, and names will not resolve because `resolvectl` is missing. The journal held only the expected `no usable TPM` warning.
  - **Upgrade.** *Upgrading: the service is restarted…*, and the main PID went from 168 to 267.
  - **Uninstall.** It listed `casa` and `ufficio`, left both directories, and removed the unit and both programs.
  - **Install again.** `active`.
- **A fixture to avoid.** A network directory made by hand with no record is removed by the daemon at its next start, as an attempt that founded nothing. So an empty directory does not survive an upgrade in this test, and that is the daemon working as designed. The uninstall listing was checked with the service stopped.

## 29. The archive on WSL2: an upgrade, a boot, an uninstall

Over the copy installed by hand in step 20, with `wsl` up. In the WSL2 shell, from `/mnt/c/<the repository root>`:

```bash
peerfectly status
tar xzf target/dist/peerfectly-0.1.0-linux-x86_64.tar.gz -C ~
sudo ~/peerfectly-0.1.0-linux-x86_64/install.sh
```

**Expect** no refusal, *Upgrading: the service is restarted…*, then a status with `wsl` up and its devices as before.

In PowerShell:

```powershell
wsl --shutdown
```

Open the Ubuntu shell again:

```bash
peerfectly status
systemctl show peerfectlyd -p ExecStart --value
```

**Expect** `wsl` up with nobody having started it, and `/usr/local/bin/peerfectlyd` with no `--allow-unsafe-location`.

```bash
sudo ~/peerfectly-0.1.0-linux-x86_64/install.sh --uninstall
ls /usr/local/bin/peerfectly* /etc/systemd/system/peerfectlyd.service
ip -br link | grep peer
sudo ~/peerfectly-0.1.0-linux-x86_64/install.sh
peerfectly status
```

**Expect**:
- the uninstall lists `wsl` as kept, and then nothing named `peerfectly` in `/usr/local/bin` or `/etc/systemd/system`;
- no `peer…` interface left;
- after the second install, `wsl` back as it was, up.

**Result**: run, 2026-10-02, passed (reported by the person who ran it).

- **The first run was refused, correctly.** *this machine is not running systemd…*, and nothing was written. `/etc/wsl.conf` had gone since step 19, so WSL had started with its own init: PID 1 was `init(Ubuntu)` and `/run/systemd/system` did not exist. The script read that as no systemd, which it was.
- **Then the steps above.** With systemd on again as in step 19, they were run and reported as passed.

# Part E — the rename to `peerfectly`

## 30. The old `mynet` installation is removed, with its keys

From `rename-to-peerfectly`. On WSL2, **with the old programs still installed**: forget each
network, answering `yes`, and `yes` again when asked about being the only admin.

```bash
mynet status
sudo mynet forget wsl
ls /var/lib/mynet/keys
```

**Expect** the keys directory empty.

Then uninstall with the old archive's script, and remove what it keeps:

```bash
sudo ~/mynet-0.1.0-linux-x86_64/install.sh --uninstall
sudo rm -rf /var/lib/mynet
sudo nft list tables
ip -br link
```

**Expect** no `inet mynet` table, and no interface whose name begins `mynet`.

**Result**: run, 2026-10-05, passed (reported by the person who ran it).

## 31. A fresh install of `peerfectly`

In PowerShell, build the archive:

```powershell
& "C:\Program Files\Git\bin\sh.exe" deploy/linux/package.sh
```

In the WSL2 shell, from the repository root:

```bash
tar xzf target/dist/peerfectly-0.1.0-linux-x86_64.tar.gz -C ~
sudo ~/peerfectly-0.1.0-linux-x86_64/install.sh
sudo peerfectly found wsl --name w
peerfectly up wsl
peerfectly status
ip -br link | grep peer
```

**Expect**:
- `peerfectlyd.service` enabled and running;
- `wsl` up;
- one interface `peer` followed by eleven hex digits;
- `sudo nft list table inet peerfectly` answering.

**Result**: run, 2026-10-05, passed (reported by the person who ran it).

# Part F — what a device spends at rest, for `on-demand-sessions`

## 32. Traffic at rest, counted on the real interface

In the testbed, `a` founds `prova` with the relay `https://204.216.216.139`, `b` joins (step 14), and
both are up. Nothing is sent through the tunnel. Then, from the repository root:

```bash
crates/linux-daemon/testbed/measure-idle.sh b a 204.216.216.139 300
docker compose -f crates/linux-daemon/testbed/compose.yaml exec a sudo -u alice peerfectly down prova
crates/linux-daemon/testbed/measure-idle.sh b a 204.216.216.139 300
```

The script counts `b`'s bytes on `eth0` by destination for five minutes and extrapolates them to a
month (see its header). The first run has the peer up; the second has it switched off.

**Expect**, after `on-demand-sessions`, in each configuration: under **100 MB a month** in total,
and under **15 MB a month** without the relay connection.

**Before** (the build of 0.1.0), three runs:

| Date | Peer | Total / month | Relay | Not relay |
|---|---|---|---|---|
| 2026-10-07, by hand | up | ~3.7 GB | ~2.5 GB | ~1.2 GB |
| 2026-10-07, by hand | switched off | ~11 GB | ~6.3 GB | ~4.6 GB |
| 2026-10-07, script, first version | up | 3.9 GB | 2.4 GB | 1.5 GB |
| 2026-10-07, script, first version | switched off | 5.6 GB | 3.3 GB | 2.2 GB |
| 2026-10-07, script | up | 5.0 GB | 2.7 GB | 2.2 GB |
| 2026-10-07, script | switched off | 2.8 GB | 1.5 GB | 1.3 GB |

The first version of the script counted a peer's multicast announcements twice, so its split is off
while its totals are right. With the peer switched off the figure varies by a factor of four between
runs, from 2.8 to 11 GB. It depends on how the dial attempts fall in the five minutes: one every
minute, each lasting thirty seconds and retrying the handshake on every path. Every run is gigabytes.

With the peer up, the direct traffic is the session's keep-alive, a packet a second each way. The
relay traffic is the same session's relayed path kept alive alongside it, plus the relay
connection itself. With the peer switched off, it is QUIC Initial packets of 1228 bytes to the peer's
addresses, answered by the peer's kernel with ICMP: the peer's daemon sends nothing, as §2.6c
requires.

**After** (the build of `on-demand-sessions`), 2026-10-07, measured twelve minutes after the join so
that the session had closed for being idle:

| Peer | Total / month | Relay | Peer, direct | Multicast (LAN) |
|---|---|---|---|---|
| up, idle | 2.3 GB | 2.25 GB | 0 | 53 MB |
| switched off | 1.16 GB | 1.11 GB | 0 | 43 MB |

**Result**: **the budget is not met.** Toward the peer the device now sends nothing at rest, in
both configurations; before, that was 1.2 to 4.6 GB a month. What remains is iroh's own traffic to the
relay: a net report every 20 to 26 seconds (`new_re_stun_timer`), which opens a fresh QUIC connection
to the relay for address discovery, and a ping every 15 seconds. Both are constants inside iroh 1.1,
not settings, and the task stops here for that decision, as the design says it should.

Three defects were found on the way and fixed, each with a test (design D14):
- **the transport's own probes looped through the tunnel.** iroh probes the tunnel addresses a peer
  advertises, those packets entered this device's tunnel, and each opened a session that probed again:
  31 GB a month toward a switched-off peer on the first run;
- **a failed on-demand attempt was retried at once,** with no rest;
- **the interface list was compared in the order the platform returned it,** which changes from one
  call to the next, so every five seconds read as a change of network, made the device reconcile with
  its neighbours, and kept every session busy so that none ever closed for being idle.

The multicast left is local-discovery announcements, on the LAN only; it is over the 15 MB line for
traffic other than the relay, and it costs no data plan.

Then with iroh's optional net-report probes off (`NetReportConfig::minimal()`: no HTTPS latency
probe, no captive-portal check; a network has one relay, so there is nothing to choose between), peer
switched off: **1.06 GB a month**, of which 1.02 GB to the relay. The probes were not the bulk. What
remains is the QUIC address discovery each net report makes — a fresh QUIC connection to the relay
every 20 to 26 seconds, about 950 MB a month — and the relay ping every 15 seconds, about 60 MB. The
interval is a constant in iroh 1.1 to 1.3; `NetReportConfig` (PR #4020) turns probes off, not the
interval down.

`minimal()` was withdrawn on the same day, before merging. Without the HTTPS probe, a device whose
QUIC to the relay gets no answer, on a network that blocks UDP, never picks a home relay and is left
with no relay at all. The binding tests caught it in CI, since their relay answers QUIC on another
port. The probes' share, about 100 MB a month at rest, is left to the change that pauses the net
report (`quiet-iroh`).

**Does it grow with the network?** Three nodes, `b` measured at rest twelve minutes after the last
session, with the same build (minimal net report), on 2026-10-07:

| Peers up | Relay | Direct to peers | Multicast (LAN) | Total / month |
|---|---|---|---|---|
| 2 | 996 MB | 0 | 65 MB | 1.06 GB |
| 1 | 997 MB | 0 | 53 MB | 1.05 GB |
| 0 | 1007 MB | 0 | 41 MB | 1.05 GB |

No. What a device spends at rest is the same whether two peers, one or none are up: the relay share is
iroh's net report and ping, once per device, and nothing goes to the peers. Only the multicast grows,
by the announcements of each peer on the same LAN, about 12 MB a month each, and on the LAN only.

## 33. Three devices, sessions on demand

`a` founds `prova`, `b` and `c` join (step 14's commands, `c` with a sealed key). Then:

1. `b` is taken down, `c` is admitted, `b` comes back up, and `c` pings `b`'s address.
2. Nothing is carried for eleven minutes, then `peerfectly peers prova` on `a`.
3. `b` is taken down, `a` signs `peerfectly rendezvous https://<relay>:8444 --network prova`, `b`
   stays down for ten minutes and comes back up; `status` on `b` 45 seconds later.
4. `a` revokes `c`; `status` and `peers` on `b` 20 seconds later.

Throughout, `b`'s log is read for what made it contact anyone (`reconciling with the neighbours`,
`spreading to the neighbours`).

**Expect**:
- `c` reaches `b`, though `b` never heard of `c` before it refused it once;
- both members reported reachable now, with their paths, although no session was open;
- `b` holds the new rendezvous within a minute of coming back;
- `b` reads `2 devices, 1 revoked` within seconds of the revocation;
- no contact logged on `b` but on its way up and after receiving something.

**Result**: run, 2026-10-07, passed, after one false start: the first run's prompt driver read
*"Nothing is signed without it"* as the end of the command, so the two signing steps signed nothing,
and they were run again.
- `ping -6` from `c` to `b`: 4 of 4.
- `peers` on `a`: `c` `reachable yes, direct (now)`, `b` `reachable yes, via relay (now)`.
- `b`, 45 s after coming back: `meet https://…:8444`.
- `b`, 20 s after the revocation: `2 devices, 1 revoked`.
- `b`'s log: `reconciling with the neighbours` when its network came up, and `spreading to the
  neighbours` after the parameter change and the revocation reached it. Nothing in between.

Run again on iroh 1.3.0 (`quiet-iroh`, before its patch), 2026-10-07: passed, the same four.
- `ping -6` from `c` to `b`: 4 of 4.
- `peers` on `a`: `b` and `c` both `reachable yes, direct (now)`.
- `b`, 45 s after coming back: `meet https://…:8444`.
- `b`, 20 s after the revocation: `2 devices, 1 revoked`.
- `b`'s log: contact on its way up and after receiving something, and nothing in between.

## 34. Traffic at rest on iroh 1.3.0, before the patch

The same as step 32, on the build of `quiet-iroh` before its patch: iroh 1.3.0 from crates.io. The
network has a rendezvous now, so its publishes are counted, and the script counts it apart: the
rendezvous (TCP 8444 to the relay's host), `relay-quic` (UDP to the relay's host: the net report's
address discovery) and `relay` (the rest: the relay connection, TCP). Thirty minutes, not five, so
that a publish every fifteen minutes falls inside:

```bash
crates/linux-daemon/testbed/measure-idle.sh b a 204.216.216.139 1800
```

with `a` up, then with `a` switched off, each twelve minutes after the join.

**Expect**: the floor of step 32, about a gigabyte a month, the same whether `a` is up or not, and
nothing to `a`.

**Result**: run, 2026-10-07.

| Build | Peer | relay-quic | relay | rendezvous | peer | multicast | Total / month |
|---|---|---|---|---|---|---|---|
| 0.1, iroh 1.1, no rendezvous (before `quiet-iroh`'s script) | up | 933 MB | 109 MB | — | 0 | 54 MB | 1.10 GB |
| iroh 1.3, unpatched | up | 1067 MB | 270 MB | 11 MB | **190 MB** | 68 MB | 1.61 GB |
| iroh 1.3, unpatched | switched off | 923 MB | 102 MB | 11 MB | 0 | 41 MB | 1.08 GB |

The floor is iroh 1.3's as it was 1.1's: the net report's address discovery, about 930 MB a month,
a new QUIC connection to the relay every 20 to 26 seconds, and the relay connection's pings and the
net report's HTTPS probes, about 100 MB. The rendezvous costs about 11 MB a month at a publish every
fifteen minutes.

**One run is not explained.** With `a` up, `b` sent and received 831 packets directly to `a` in the
thirty minutes, 190 MB a month, and twice its usual traffic to the relay: a session, open for part
of the window, that nothing logged at `info` accounts for. None of the other three runs with `a`
up showed it: thirty minutes on 1.1 before, and afterwards five minutes sampled every second and
thirty sampled every five seconds on the same 1.3 build, with nothing from `a` but its
announcements. It is recorded rather than averaged away, and watched for in the runs after the
patch.

## 35. Traffic at rest on the patched iroh

As step 34, on the build of `quiet-iroh` with its patch: iroh from the project's fork
(`nohostalgia/iroh`, `peerfectly/1.3`, `2fc2b89a97`), the net report paused while no connection is
open, and the relay pinged once a minute. The relay on the VPS updated to the image built from the
same commit, with `ping_interval_secs = 60` in its `relay.toml`.

**Expect** (`transport-iroh` spec, *An endpoint with no connection spends almost nothing*): nothing
to `relay-quic`, the relay share under 20 MB a month, and nothing to `a`.

**Result**: run, 2026-10-08, **passed**, after two findings that each had to be fixed first.

| Build | Peer | relay-quic | relay | rendezvous | peer | multicast | Total / month |
|---|---|---|---|---|---|---|---|
| fork, relay not yet updated | up | 0 | 57.8 MB | 11.4 MB | 0 | 35.0 MB | 104 MB |
| fork, relay not yet updated | switched off | 0 | 45.6 MB | 11.4 MB | 0 | 23.3 MB | 80 MB |
| fork, relay updated | switched off | 0 | 13.7 MB | 11.3 MB | 0 | 23.3 MB | **48 MB** |
| fork, relay updated | up | 320 packets | 510 MB | 11.3 MB | **392 MB** | 53.2 MB | 1.13 GB |
| fork, relay updated, replaced sessions closed | up | 0 | 13.1 MB | 11.6 MB | 0 | 35.2 MB | **60 MB** |
| the same, again | up | 0 | 14.3 MB | 11.3 MB | 0 | 35.7 MB | **61 MB** |

**The address discovery is gone at rest**: no UDP to the relay in any run but the one with a session
left open, against about 930 MB a month before.

**The relay set the pace until it was updated.** Timed at rest before, `b` exchanged three packets in
and two out with the relay every sixteen seconds: the relay's fifteen and jitter, which reset the
device's minute each time. The redeploy on the VPS had not taken (`docker compose` was run from the
wrong directory). Run again from the checkout, the exchange came once a minute, and the relay's share
fell to about 14 MB.

**A replaced session was never closed.** The fourth run is the unexplained run of step 34 again: a
session open the whole window, its paths kept alive every three seconds and the net report running
because iroh saw a connection. When `a` and `b` dial each other at the same moment, two connections
open; each node keeps the one it registered last, and dropped the other from its table without
closing it. Where both kept the same one, the other stayed open in the transport for good. It is
closed now when it is replaced (`Node::opened`, the test
`a_session_replaced_by_another_to_the_same_device_is_closed`), and the two runs after it are clean.

Within the budget with the peer up or switched off: under 20 MB to the relay, nothing to `a` at rest,
and the total under 100 MB, of which the LAN's multicast is 23 to 36 MB.

## 36. A session after a rest, and the address discovery while one is open

In the testbed on the same build, `a` and `b` in a network, nothing carried for eleven minutes, then
from `b`:

```bash
ping -6 -c 5 -W 5 <a's address>
ping -6 -i 1 -c 300 -q <a's address>
```

with UDP to the relay's host counted on `b` during the second, and again for the twelve idle minutes
after it.

**Expect**: the first packet answered; while the session is open, one QUIC connection kept for address
discovery, not a new one for each report.

**Result**: run, 2026-10-08, passed.
- After eleven idle minutes, 5 of 5 answered, the first in 9 ms against about 1 ms for the others:
  the session opening again.
- Five minutes of a session in use: 38 packets, 18 KB, to the relay over UDP, against about 120 KB in
  five minutes on 1.3 unpatched, where every report opened a connection of its own (step 34).
- The twelve minutes after it, most of them with the session still open until it closed for being
  idle: 97 packets, 38 KB.

## 37. Names are DNS labels, and a device is renamed

In the testbed, with step 14's commands:

1. `a` founds `prova` with `--name Laptop`.
2. `b` joins with `--name "PC di Giovanni"`.
3. `b` joins with `--name b`, and `a` admits it.
4. On `a`: `sudo peerfectly rename b Studio --network prova`.
5. On both, ten seconds later, each node's resolver asked for `studio`, `b` and `laptop` under
   `.prova.internal`, as in step 14.

**Expect**:
- the founding to say the name is kept in lower case, and `status` to show `laptop.prova.internal`;
- the second join refused before anything is made, with `pc-di-giovanni` offered, and `b` holding no
  network;
- the rename confirmed as ``rename … to `studio` ``, in lower case, and signed with the passphrase;
- `studio` answering on both nodes with `b`'s address, `b` answering on neither, and `b` calling
  itself `studio.prova.internal`.

**Result**: run, 2026-10-09, passed after one fix.
- **The founding was refused by the command line itself:** *"the act to be signed is not the act
  that was asked for. Nothing was signed."* The command line checks the act it signs against what
  was typed, and compared the typed `Laptop` with the daemon's `laptop`. A signature asked here, as
  on Linux, goes through that check; one made inside the daemon, as on Windows, does not, which is
  why the daemon's tests did not show it. Names are now compared as the daemon keeps them, a
  rename's new name is checked the same way (it was not checked at all), and the tests
  `a_founding_typed_in_upper_case_is_the_one_asked_for` and
  `a_rename_must_carry_the_name_typed_in_lower_case` cover both.
- After it: ``this device is named `laptop`: a device's name is kept in lower case.``, and `status`
  on `a` read `laptop.prova.internal`.
- The second join: *"a device's name may hold only letters from a to z, digits and hyphens, and ' '
  is none of them; `pc-di-giovanni` would do"*, with no passphrase asked, and `b` holding no network.
- The rename: confirmed as ``rename ab0e-11c5-aa66-0e24 to `studio` ``, signed, exit 0.
- On `a` and on `b`: `studio` answered `fdff:5685:d06e:3380:fc17:ab8e:ec24:d5e4`, `b` answered
  nothing, `laptop` answered `a`'s address. `status` on `b`: `studio.prova.internal`.

Two things read badly in that run and were changed after it, with tests rather than another run:
the waiting line read *"renaming of studio [ab0e…] to studio"*, as the device already went by the new
name, and now reads *"renaming of [ab0e…] to studio"*; and the confirmation named the device by id
alone, and now names it as typed, as a revocation's does: ``rename `b` (ab0e…) to `studio` ``.
