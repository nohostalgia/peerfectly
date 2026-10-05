# Security

peerfectly decides who can join your network, so a flaw in it can matter. If you find one, thank
you, and please report it privately first.

## Status

**The code has not been audited.** It's pre-release (0.1), maintained by one person, and the
protocol may still change. Only the latest `main` is supported: there are no older releases to
patch.

## How to report

Use GitHub's private vulnerability reporting: on the repository's **Security** tab, choose **Report
a vulnerability**. Only you and the maintainers see the report.

Please **don't** open a public issue, pull request or discussion for it.

## What helps

- What's affected: the crate or file, and the commit or version.
- How to reproduce it, as small as you can make it.
- What an attacker gains, and what they need first: network position, a device in the network, a
  stolen key, a local account.
- If you have one, how you'd fix it.

## What happens next

- **Acknowledgement within 7 days.** It's one person, not a team on call.
- **An assessment,** shared with you: whether it's a vulnerability, how severe, and what the fix
  looks like.
- **A fix, then disclosure.** The default is to publish an advisory when the fix is out, and no
  later than 90 days after your report, unless we agree on something else. Credit goes to you in the
  advisory, if you want it.

## In scope

The daemon, the command line, the protocol and its formats, the installers and deploy files in this
repository, and the relay and rendezvous configuration in `deploy/server`.

Bugs in dependencies, such as iroh, Wintun or the TSS libraries, belong to their projects. If one
affects peerfectly in a particular way, tell us as well.
