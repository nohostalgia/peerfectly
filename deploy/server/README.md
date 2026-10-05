# The server: relay and rendezvous

One image, two containers:

- **`relay`** — `iroh-relay` 1.1.0, built from this workspace's lockfile. It carries traffic between devices that cannot reach each other directly, and tells each device the address the internet sees it at.
- **`rendezvous`** — `peerfectly-rendezvous`. It holds each device's sealed, signed record of where it can be reached.

Neither can read a network's traffic or join one. What their operator sees is at the end.

## What is where

| File | What |
|---|---|
| `Dockerfile` | Builds both binaries and the runtime image. Built from the repository root. |
| `Dockerfile.dockerignore` | Keeps build output, the phone, history and anything key-like out of the build. |
| `compose.yaml` | The two services, their ports and their restrictions. |
| `relay.toml` | The relay's default configuration, copied into the image. |
| `relay-entrypoint.sh` | Puts the certificate's paths into the relay's configuration, then starts it. |

## Ports

| Host | Service | Why |
|---|---|---|
| 80/tcp | relay | captive-portal checks |
| 443/tcp | relay | the relay, over HTTPS |
| 443/udp | relay | QUIC address discovery, on the relay's own port |
| 8444/tcp | rendezvous | the rendezvous, over HTTPS |

Open exactly these in the host's firewall **and** in the cloud provider's security list, plus SSH restricted to where you administer from.

Inside, the services listen on 8080, 8443 and 8444 as an unprivileged user, and Docker publishes them. That is why no capability is needed, not even the one for low ports.

## The certificate

Both services serve **the same** certificate, so a network that pins it verifies both.

**Where it is read from:**
- by default `/etc/peerfectly/certs/relay.crt` and `relay.key` on the host;
- `PEERFECTLY_CERT_DIR` moves the directory;
- `PEERFECTLY_CERT` and `PEERFECTLY_KEY`, set in `compose.yaml`'s `environment`, name other files inside it (for example `fullchain.pem` and `privkey.pem`). Both services read them. Do not give either service a path of its own.

The image never contains a certificate or a key.

**Installing it on the host:**

```sh
sudo mkdir -p /etc/peerfectly/certs
sudo cp relay.crt relay.key /etc/peerfectly/certs/
sudo chown root:10001 /etc/peerfectly/certs/relay.crt /etc/peerfectly/certs/relay.key
sudo chmod 0644 /etc/peerfectly/certs/relay.crt
sudo chmod 0640 /etc/peerfectly/certs/relay.key
```

**Its expiry:**

```sh
openssl x509 -in /etc/peerfectly/certs/relay.crt -noout -enddate -fingerprint -sha256
```

Write the date down.

**Replacing it.** A network that pins this certificate trusts it and nothing else. Replacing it with one that has a different key needs each such network moved with `peerfectly relay <address>` first, which pins the new one and keeps the old reachable for the transition. Swapping the file alone strands every device of those networks.

## Build and start

On the server, from a copy of the repository:

```powershell
# On your machine, from the repository root: the committed tree, nothing else.
git archive --format=tar.gz -o peerfectly-src.tar.gz HEAD
scp peerfectly-src.tar.gz <user>@<server>:
```

```sh
# On the server.
mkdir -p ~/peerfectly && tar -xzf ~/peerfectly-src.tar.gz -C ~/peerfectly
cd ~/peerfectly
docker compose -f deploy/server/compose.yaml up -d --build
docker compose -f deploy/server/compose.yaml ps
```

Building on the server makes the image native to its architecture. Rust needs a couple of gigabytes of memory to build this. On a smaller machine, build on yours for the server's platform and load it there:

```powershell
docker buildx build --platform linux/arm64 -f deploy/server/Dockerfile -t peerfectly-server --load .
docker save peerfectly-server -o peerfectly-server.tar
scp peerfectly-server.tar <user>@<server>:
```

```sh
docker load -i peerfectly-server.tar
docker compose -f deploy/server/compose.yaml up -d
```

Use `linux/amd64` for an x86 server; `uname -m` on the server says which.

## Replacing a deployment from before the rename

Before 2026-10-03 the product was called `mynet`, and its server ran from the image `mynet-server`
with the certificate under `/etc/mynet/certs`. The rename changed the protocol too. The
rendezvous's records are sealed under a context that has changed, so what the old rendezvous held is
useless to the new devices, and nothing needs to be kept.

**The relay's certificate can stay.** The relay speaks iroh's relay protocol, which carries no
product name, so a new network can pin the same certificate. On the server:

```sh
# The old containers, from the old checkout.
cd ~/mynet && docker compose -f deploy/server/compose.yaml down
# The certificate, moved to where the new image looks for it.
sudo mv /etc/mynet /etc/peerfectly
```

Then build and start as above, from a checkout of the new source. If an override of
`compose.yaml` set `MYNET_CERT`, `MYNET_KEY` or `MYNET_CERT_DIR`, rename them to
`PEERFECTLY_CERT`, `PEERFECTLY_KEY` and `PEERFECTLY_CERT_DIR`. Once the new containers answer, the old
image and checkout can go:

```sh
docker image rm mynet-server
rm -rf ~/mynet ~/mynet-src.tar.gz
```

## Rolling back

```sh
docker compose -f deploy/server/compose.yaml down
```

Then start whatever ran before. The certificate did not change, so nothing on the devices did.

## Logs

```sh
docker compose -f deploy/server/compose.yaml logs --tail 50
```

- **The relay** runs at `RUST_LOG=warn`. At `info` and below it names connecting nodes.
- **The rendezvous** writes one line when it starts and nothing per request.

Neither log should carry a node identity, a key or a published address. Raising the level to debug a problem changes that: lower it again afterwards.

## Who may use the relay

`relay.toml` says `access = "everyone"`, with limits on new connections a second and on each client's bandwidth. To change them, mount your own `relay.toml` at `/etc/peerfectly/relay.toml`, keeping `@PEERFECTLY_CERT@` and `@PEERFECTLY_KEY@` as the certificate's paths.

An allowlist of your own devices is a later change.

## What the operator sees

**The relay:**
- which node identities connect, and from which addresses;
- when, and how much they send.

It carries traffic it cannot read: sessions are end-to-end encrypted between devices.

**The rendezvous:**
- the addresses that publish and fetch;
- a pseudonym per record, and records sealed with a key derived from the network's identifier.

It is never told a network's identifier, so it cannot read the addresses in a record. It cannot forge a record either: devices sign their own.

**Both:**
- can refuse service, or delay it;
- cannot admit anybody to a network, or read what devices say to each other.
