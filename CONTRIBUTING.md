# Contributing to peerfectly

Thanks for looking. A few things are worth knowing before you open a pull request.

## The contributor licence agreement

peerfectly is published under the AGPL-3.0, and the project also wants to be able to offer it under
other terms, for example a commercial licence for a company that can't ship AGPL code. That's only
possible if the project has permission to relicense every line in it, yours included.

So before your first pull request is merged, you'll be asked to sign the [CLA](CLA.md). A bot
comments on the pull request with a link, and signing takes a minute. You keep the copyright on what
you write. The CLA grants the project a licence to it, it doesn't take it from you. You sign once,
not per pull request.

## Before a big change

Open an issue or a discussion first, so nobody spends a week on something that won't be merged.
That matters most for the protocol. The domain-separation tags, the ALPNs, the address derivation
contexts and the formats in the `FORMAT.md` files are what two devices agree on. Changing one is a
protocol change, and two versions stop talking to each other.

## Building and testing

You need [rustup](https://rustup.rs/). `rust-toolchain.toml` pins the Rust every build uses, and
rustup installs it the first time you run `cargo` here. Before you push:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

On Linux, add `--exclude windows-daemon` to the last two, and install `libtss2-dev` and
`pkg-config` first.

Clippy runs with the workspace's lints, and a few of them deny rather than warn: no `unwrap`, no
`panic!`, no unchecked indexing or arithmetic outside tests. The Linux daemon's tests that need a
kernel, a TPM and root are `#[ignore]`d. They run in the Docker testbed under
`crates/linux-daemon/testbed/`.

## What CI checks

Every pull request runs [`ci.yml`](.github/workflows/ci.yml), and its jobs are required: a pull
request with one of them red isn't merged.

| Job | What it runs |
|---|---|
| `fmt` | `cargo fmt --all --check` |
| `windows` | clippy with warnings as errors, and the tests, the whole workspace |
| `linux` | the same without `windows-daemon` |
| `deny` | [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) against [`deny.toml`](deny.toml): licences, RustSec advisories, and crates.io as the only source |
| `secrets` | [`gitleaks`](https://github.com/gitleaks/gitleaks) on the tree, and on every commit the pull request adds |

A new dependency has to come from crates.io under a licence `deny.toml` allows. If it needs one that
isn't there, say so in the pull request: the list is short on purpose, and every entry is compatible
with the AGPL. A test string that looks like a secret and isn't takes an inline `gitleaks:allow`
comment.

## What a good pull request looks like here

- **One change, explained.** Pull requests are squash-merged, so the title and description become
  the commit message. Say what changed and why.
- **Tests for behaviour.** If it changes what the software does, a test should fail without it.
- **Comments say why.** The code around you explains the reasons for its decisions, and yours
  should too. Match the style of the file you're in.
- **What a test can't show gets written down.** Some behaviour only shows on a real machine with a
  real driver, a TPM or a second device. That goes in the crate's `VERIFICATION.md` as a step, with
  what you expect written *before* you run it. A step you haven't run says `not run`.
- **English** for code, comments and documentation.

## Your commits are public

The name and email on your commits are visible to anyone. If you'd rather not publish your email,
GitHub gives you a `noreply` address under *Settings → Emails*.

## Security issues

Not here: see [SECURITY.md](SECURITY.md).
