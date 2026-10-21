# The peerfectly relay

Devices in a peerfectly network talk to each other directly whenever they can. The relay is what
they lean on when they can't. It forwards traffic between devices that can't reach each other
directly, for example both behind strict NATs, and tells each device the address the internet sees
it at, which is what lets two devices find a direct path in the first place.

It's one program in one container, `peerfectly-relay`:

- **a convesso relay**, on 8443 over UDP and TCP;
- **its key, over HTTPS**, on 443. A device founding a network with `--relay <this host>` asks it
  which key and port the relay serves, shows the key to its person, and signs nothing until they
  confirm it.

It can't read what devices say to each other, and it can't let anyone into a network. What the
operator does see is spelled out [at the end](#what-the-operator-sees).

## What you need

- A Linux host with a public address, and Docker with the Compose plugin.
- These ports open, both in the host's firewall and in your cloud provider's security rules:

  | Port | What for |
  |---|---|
  | 8443/udp | the relay |
  | 8443/tcp | the relay, for networks where UDP does not pass |
  | 443/tcp | the relay's key, over HTTPS |

Inside the container it listens on 8443 and 8444 as an unprivileged user, and Docker maps 443 to
8444. It runs with a read-only filesystem and no capabilities at all; the volume is its only
writable place.

## Building the image

From the root of this repository, for the server's architecture (`uname -m` on the server: `x86_64`
is `linux/amd64`, `aarch64` is `linux/arm64`):

```sh
docker buildx build --platform linux/arm64 -f deploy/server/Dockerfile -t peerfectly-relay --load .
docker save peerfectly-relay -o peerfectly-relay.tar
scp peerfectly-relay.tar deploy/server/compose.yaml you@203.0.113.10:
```

## Running it

On the server, in the directory the two files were copied to:

```sh
docker load -i peerfectly-relay.tar
docker compose -f compose.yaml up -d
docker compose -f compose.yaml logs relay
```

The log's first lines are the relay's key and where it listens:

```text
created a new identity in /data/relay.key
relay key 1c23b31d465a430ab24cc9e7990dd18ed67800950f7c3d035c3f6cb7747e5a89
relay on udp 0.0.0.0:8443 and tcp 0.0.0.0:8443; its key over https on 0.0.0.0:8444
```

Keep that key at hand: a person founding a network on this host compares it with what their device
shows. To check the key is served:

```sh
curl -k https://203.0.113.10/relay
```

`-k` because the certificate is the relay's own, made on first start: no client checks it, and the
key is what is confirmed.

## Point a network at it

```sh
peerfectly found casa --relay 203.0.113.10
```

The device asks the host, shows `<key>@203.0.113.10:8443` and the key in groups of four, and signs
only once its person confirms. `--relay <key>@203.0.113.10:8443`, written out, asks nothing.

## Configuration

Each setting is an environment variable on the service, and each has a default:

| Variable | Default | What |
|---|---|---|
| `PEERFECTLY_PUBLIC_PORT` | the relay's own port | the port devices reach the relay on, when the host publishes it on another number |
| `PEERFECTLY_RELAY_CONFIG` | none | a file of the relay's own TOML, `[limits]` or `[allowlist]`, added to its configuration |
| `PEERFECTLY_DATA` | `/data` | where the identity and the certificate are kept |
| `PEERFECTLY_RELAY_LISTEN` | `0.0.0.0:8443` | where the relay listens, UDP and TCP |
| `PEERFECTLY_KEY_LISTEN` | `0.0.0.0:8444` | where the key is served |

## Updating

Build and load a new image as above, then `docker compose -f compose.yaml up -d`. The volume keeps
the identity and the certificate, so the key does not change and nothing changes on the devices.

## Logs

```sh
docker compose -f compose.yaml logs --tail 50
```

The relay writes its key and where it listens when it starts, and nothing per request.

## What the operator sees

- which device keys connect to the relay, and from which addresses;
- when they connect, and how much they send;
- which addresses ask for the relay's key.

It can't read the traffic: it's end-to-end encrypted between devices. It can refuse service, or
delay it. It can't admit anybody to a network.

## What's in this directory

| File | What |
|---|---|
| `Dockerfile` | builds the program and the runtime image, from the repository root |
| `Dockerfile.dockerignore` | keeps build output, history and anything key-like out of the build |
| `compose.yaml` | the service, its ports, its volume and its restrictions |
