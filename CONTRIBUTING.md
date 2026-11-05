# Contributing to hydra

Thanks for helping. This page covers building and testing hydra, how the code is laid out, and the rules every change keeps.

## Build and test

You need Rust 1.85 or newer, on Linux. On another OS, use Docker.

```bash
scripts/check.sh    # format check, clippy, unit tests, release build: what CI runs
```

With Docker:

```bash
docker run --rm -v "$PWD:/src" -w /src rust:1-slim-bookworm sh scripts/check.sh
```

### End-to-end tests

`scripts/netns-forward.sh` builds a small network out of Linux network namespaces: a client, the hydra server, and stand-ins for Windscribe's servers. It checks real forwarding:

- entries, ports and several addresses;
- 1:1 NAT;
- datacenters spread over several servers, and followed through DNS;
- address ranges, routed and on the server's network;
- `doctor` and `tune`;
- `hydra setup`, driven in a pseudo-terminal.

It needs root and changes some host-wide settings, so run it in a throwaway VM or a privileged container:

```bash
docker run --rm --privileged -v "$PWD:/src" -w /src rust:1-slim-bookworm sh -c \
  'apt-get update -qq && apt-get install -y -qq nftables iproute2 python3 conntrack procps >/dev/null &&
   cargo build --release && bash scripts/netns-forward.sh'
```

It ends with `ALL PASS`.

`scripts/netns-bench.sh` is a rough throughput test of the normal path against the fast path. It needs `iperf3`.

## Code layout

```
src/main.rs         the CLI and flag parsing
src/profile.rs      the shareable profile (JSON)
src/nft.rs          the nftables table, inet hydra
src/state.rs        the server's saved entries (/etc/hydra/entries.json)
src/setup.rs        hydra setup: the guided flow, behind a Ui trait (a terminal, or scripted answers in tests)
src/look.rs         hydra setup's look: palette, banner, cards, flags
src/datacenters.rs  Windscribe's public list of locations: datacenters and their WireGuard hostnames
src/host.rs         default route and gateway, local addresses and ranges, hostname
src/probe.rs        check-range: whether a range is routed to the server
src/audit.rs        doctor's checks and findings, and tune
src/sys.rs          filesystem and command access, with fixtures for tests
contrib/            systemd units
scripts/            checks, end-to-end tests, benchmark
```

## Rules every change keeps

1. **Profiles hold no secrets.** No private keys, preshared keys, session tokens, or obfuscation parameters. Profiles reject unknown fields (`deny_unknown_fields`); keep it that way.
2. **Passthrough only.** hydra forwards UDP unchanged. No decryption or re-wrapping, no NFQUEUE, and no native code in the data path.
3. **One entry, one datacenter.** An entry (address and port) forwards to one Windscribe datacenter, never to a whole region. The apps match a profile's front by `datacenter_id`.
4. **The README and the CLI's help describe what ships.** No plans or future work.
5. **Tests stay off the internet.** Use documentation addresses (RFC 5737) where an address needn't be public, and keep public-looking ones inside fixtures and network namespaces. Never run `hydra up` against Windscribe's servers from CI.
6. **Few dependencies.** Justify every new crate. CI runs `cargo audit`.
7. **`doctor` stays read-only.** `tune` only raises numbers or turns offloads on, changes network cards only with `--nic`, and never touches nftables tables other than `inet hydra`.

## Pull requests

- Keep each pull request to one change, with tests.
- Run `scripts/check.sh` first. For changes to forwarding, setup, or the host checks, run the end-to-end tests too.
- hydra is developed in Windscribe's own repository and published here. Once accepted, your change reaches this repository with the next update.
