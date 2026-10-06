# The peerfectly server

Devices in a peerfectly network talk to each other directly whenever they can. This server is what
they lean on when they can't. It's two small services, built into one image and run as two
containers:

- **`relay`**: [`iroh-relay`](https://github.com/n0-computer/iroh), the exact version the rest of
  the workspace is tested against. It forwards traffic between devices that can't reach each other
  directly, for example both behind strict NATs, and tells each device the address the internet sees
  it at, which is what lets two devices find a direct path in the first place.
- **`rendezvous`**: `peerfectly-rendezvous`. Each device leaves a sealed, signed note here saying
  where it can be reached, and the other devices of its network pick it up.

Neither can read what devices say to each other, and neither can let anyone into a network. What
the operator does see is spelled out [at the end](#what-the-operator-sees).

## What you need

- A Linux host with a public address, and Docker with the Compose plugin.
- About 2 GB of memory to build the image there. On a smaller machine, build it somewhere else:
  see [Building on another machine](#building-on-another-machine).
- These ports open, both in the host's firewall and in your cloud provider's security rules:

  | Port | Service | What for |
  |---|---|---|
  | 443/tcp | relay | the relay, over HTTPS |
  | 443/udp | relay | QUIC, which devices use to learn their public address |
  | 80/tcp | relay | captive-portal checks |
  | 8444/tcp | rendezvous | the rendezvous, over HTTPS |

Inside the containers the services listen on 8080, 8443 and 8444 as an unprivileged user, and
Docker maps them to the ports above. They run with a read-only filesystem and no capabilities at
all.

## Running it

The example uses the address `203.0.113.10`. Replace it with your server's.

### 1. A certificate

Both services serve the same certificate. Devices **pin** it: they trust this certificate and
nothing else, so it doesn't need to come from a public authority. A self-signed one works, and is
the usual choice for a server on a bare IP address.

On the server, with OpenSSL 3:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
  -keyout relay.key -out relay.crt -subj "/CN=203.0.113.10" \
  -addext "subjectAltName=IP:203.0.113.10" \
  -addext "basicConstraints=critical,CA:FALSE"
```

Three details matter:

- **`subjectAltName`** has to name exactly what devices will connect to: `IP:` for an address,
  `DNS:relay.example.org` for a name.
- **`CA:FALSE`** is not optional. Without it, OpenSSL marks the certificate as an authority, and
  devices refuse an authority as a server's own certificate.
- **Ten years (`-days 3650`) is on purpose.** Replacing a pinned certificate means moving every
  network that uses it (see [Replacing the certificate](#replacing-the-certificate)), so make it
  long-lived.

Put it where the containers read it, readable by the services' group (10001) and nobody else:

```sh
sudo mkdir -p /etc/peerfectly/certs
sudo mv relay.crt relay.key /etc/peerfectly/certs/
sudo chown root:10001 /etc/peerfectly/certs/relay.crt /etc/peerfectly/certs/relay.key
sudo chmod 0644 /etc/peerfectly/certs/relay.crt
sudo chmod 0640 /etc/peerfectly/certs/relay.key
```

Note its fingerprint. You'll compare it on the first device:

```sh
openssl x509 -in /etc/peerfectly/certs/relay.crt -noout -fingerprint -sha256 -enddate
```

### 2. Start the services

```sh
git clone https://github.com/nohostalgia/peerfectly.git
cd peerfectly
git checkout v0.1.0
docker compose -f deploy/server/compose.yaml up -d --build
docker compose -f deploy/server/compose.yaml ps
```

The first build takes a while: it compiles both programs from source. Check out the release tag
that matches the version your devices run.

### 3. Point a network at it

On the device that founds the network:

```sh
peerfectly found home --relay https://203.0.113.10 --rendezvous https://203.0.113.10:8444
```

It fetches the relay's certificate and shows its fingerprint: check it's the one from step 1 before
you confirm. Because the rendezvous runs on the same host, the same pinned certificate covers it.
Devices that join later get both addresses, and the pin, from the network itself.

## Configuration

The defaults work as they are. For anything else, keep your changes in files of your own next to
`compose.yaml`, so that updating the checkout never overwrites them.

**The certificate in another place, or under other names**, for example files from your own CA:

```sh
# deploy/server/.env: Compose reads it from the compose file's directory.
PEERFECTLY_CERT_DIR=/srv/peerfectly/certs
```

```yaml
# deploy/server/compose.local.yaml
services:
  relay:
    environment:
      PEERFECTLY_CERT: /etc/peerfectly/certs/fullchain.pem
      PEERFECTLY_KEY: /etc/peerfectly/certs/privkey.pem
  rendezvous:
    environment:
      PEERFECTLY_CERT: /etc/peerfectly/certs/fullchain.pem
      PEERFECTLY_KEY: /etc/peerfectly/certs/privkey.pem
```

`PEERFECTLY_CERT_DIR` is the directory on the host. `PEERFECTLY_CERT` and `PEERFECTLY_KEY` are paths
*inside* the container, under `/etc/peerfectly/certs`. Give both services the same two: they serve
one certificate.

**The relay's own settings.** The image carries [`relay.toml`](relay.toml), which lets anyone use
the relay within limits: 5 new connections a second (bursts of 50), and about 20 Mbit/s per client.
To change them, copy it to `deploy/server/relay.local.toml`, edit the copy, and mount it:

```yaml
# deploy/server/compose.local.yaml
services:
  relay:
    volumes:
      - ./relay.local.toml:/etc/peerfectly/relay.toml:ro
```

For example, to allow more bandwidth per client:

```toml
[limits.client.rx]
bytes_per_second = 6_250_000   # about 50 Mbit/s
max_burst_bytes = 25_000_000
```

Leave the `@PEERFECTLY_CERT@` and `@PEERFECTLY_KEY@` placeholders as they are: the container fills
them in from the two settings above when it starts.

With a `compose.local.yaml`, name both files in every command:

```sh
docker compose -f deploy/server/compose.yaml -f deploy/server/compose.local.yaml up -d --build
```

## Updating

```sh
cd peerfectly
git fetch --tags
git checkout v0.2.0
docker compose -f deploy/server/compose.yaml up -d --build
```

The certificate stays where it is, so nothing changes on the devices.

## Building on another machine

On your own computer, from the repository, build for the server's architecture (`uname -m` on the
server: `x86_64` is `linux/amd64`, `aarch64` is `linux/arm64`):

```sh
docker buildx build --platform linux/arm64 -f deploy/server/Dockerfile -t peerfectly-server --load .
docker save peerfectly-server -o peerfectly-server.tar
scp peerfectly-server.tar you@203.0.113.10:
```

Then on the server, from the checkout, without `--build`:

```sh
docker load -i peerfectly-server.tar
docker compose -f deploy/server/compose.yaml up -d
```

## Replacing the certificate

Every network that uses this server has its certificate signed into its configuration. Swapping the
files on the server, with a new key, cuts all of them off.

To move a network to a new certificate, generate it, serve it from a **second** address or port,
and run `peerfectly relay <new address>` on the network's admin. That pins the new certificate and
keeps the old one reachable while devices catch up. Retire the old one only once every network
has moved.

## Logs

```sh
docker compose -f deploy/server/compose.yaml logs --tail 50
```

- **The relay** runs at `RUST_LOG=warn`. At `info` and below it names the devices that connect.
- **The rendezvous** writes one line when it starts and nothing per request.

So by default neither log holds a device identity, a key or an address. Raising the level to chase a
problem changes that: lower it again afterwards.

## What the operator sees

**The relay:**
- which device identities connect, and from which addresses;
- when they connect, and how much they send.

It can't read the traffic: it's end-to-end encrypted between devices.

**The rendezvous:**
- the addresses that publish and fetch notes;
- one pseudonym per note, and the notes themselves, sealed with a key derived from the network's
  identifier.

It is never told a network's identifier, so it can't open the notes, and since devices sign their
own, it can't forge one either.

**Both** can refuse service, or delay it. Neither can admit anybody to a network or read what
devices say to each other.

## What's in this directory

| File | What |
|---|---|
| `Dockerfile` | builds both programs and the runtime image, from the repository root |
| `Dockerfile.dockerignore` | keeps build output, history and anything key-like out of the build |
| `compose.yaml` | the two services, their ports and their restrictions |
| `relay.toml` | the relay's default configuration, copied into the image |
| `relay-entrypoint.sh` | puts the certificate's paths into the relay's configuration, then starts it |
