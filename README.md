# rVPN Core

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

rVPN is a stealth VPN with end-to-end encryption. Traffic is encrypted on your device and decrypted only by its destination. The relay server in between forwards ciphertext it cannot read.

This repository contains the core Rust implementation: the client, server, protocol libraries, and mobile FFI bindings. The native macOS, iOS, and Android apps are maintained separately.

## Architecture

- **Double Ratchet Algorithm** (from Signal) for continuous key rotation and forward secrecy
- **X3DH key exchange** for initial handshake without passwords or accounts
- **WebSocket over TLS** transport - traffic is indistinguishable from normal HTTPS
- **Pooled multiplexing** - many flows share a small set of long-lived connections, with credit-based flow control and TLS session resumption
- **Reverse proxy** - the server hosts a real website on port 443, the VPN endpoint is hidden behind it
- **Per-instance decoy pages** - plain HTTPS probes get a realistic, randomly chosen login page, so no two servers present the same face
- **TLS fingerprint mimicry** - connections mimic Chrome, Firefox, or Safari fingerprints
- **Stats dashboard** - the CLI serves a live MRTG-style traffic page with a JSON API

## Repository Structure

```
rvpn/
  Cargo.toml         Workspace manifest
  Cargo.lock         Dependency lockfile
  crates/
    rvpn-core/       Protocol, cryptography, packet handling
    rvpn-client/     CLI client binary (SOCKS5 and TUN modes)
    rvpn-server/     Server binary (relay, NAT, TUN)
    rvpn-mobile/     FFI bindings for iOS/macOS/Android
```

## Building

Requires Rust 1.75+.

```bash
cd rvpn

# Build everything
cargo build --release

# Build specific package
cargo build --release --package rvpn-client
cargo build --release --package rvpn-server
cargo build --release --package rvpn-mobile

# Run tests
cargo test

# Check formatting
cargo fmt --check

# Lint
cargo clippy
```

### Cross-compilation

Install [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) and [zig](https://ziglang.org/):

```bash
# macOS (Apple Silicon)
cargo zigbuild --release --target aarch64-apple-darwin

# macOS (Intel)
cargo zigbuild --release --target x86_64-apple-darwin

# Linux x86_64
cargo zigbuild --release --target x86_64-unknown-linux-gnu

# Linux ARM64
cargo zigbuild --release --target aarch64-unknown-linux-gnu

# Linux ARMv7
cargo zigbuild --release --target armv7-unknown-linux-gnueabihf

# Linux musl (static)
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

### Desktop CLI builds

On Windows with the MSVC Rust toolchain installed, build the command-line client:

```powershell
cd rvpn
cargo build --release --locked --package rvpn-client --package rvpn-server --bins
.\target\release\rvpn.exe --help
.\target\release\rvpn-server.exe --help
```

The [CLI build workflow](.github/workflows/cli-client.yml) builds Windows
x86_64, Linux x86_64/ARM64, and macOS Intel/Apple Silicon clients and servers.
The client (`rvpn`) and server (`rvpn-server`) are separate executables. Each
platform job uploads separate client and server artifacts with checksums. Use
SOCKS5 mode with the same client configuration as other desktop builds.

The workflow runs on relevant pushes, pull requests, and manual dispatch. After
all platform jobs pass on `main`, it publishes separate client and server
archives plus `SHA256SUMS.txt` as a dated nightly prerelease. It also rebuilds
and publishes nightly at 02:00 UTC even when no source files changed.
Windows TUN mode requires a compatible TUN driver and elevated privileges;
the workflow checks CLI startup, not a live VPN connection. The server's
automatic TUN route setup currently uses Linux `ip` commands, so server TUN
mode also needs platform-specific routing work outside Linux.

### Mobile library

The `rvpn-mobile` crate produces a static library (`librvpn_mobile.a`) for linking into native iOS, macOS, and Android apps. Build it with the appropriate feature flag:

```bash
# iOS
cargo build --release --package rvpn-mobile --target aarch64-apple-ios --features ios-direct-tun

# macOS
cargo build --release --package rvpn-mobile --target aarch64-apple-darwin --features macos-direct-tun

# Android
cargo build --release --package rvpn-mobile --target aarch64-linux-android --features android-direct-tun
```

The native app source code (Swift, Kotlin/Flutter) is not included in this repository.

### Routing rule data

The client first classifies proxied destinations by domain, then by resolved IP.
Configured tunnel domains and networks take priority over bypass lists; unmatched
traffic goes through the VPN. With `block_ads = true`, matching ad domains are
blocked before normal domain routing. The desktop CLI uses the shared
`rvpn-split-tunnel` rule engine for SOCKS5 and optional HTTP/DNS proxy modes.

The built-in data is a fixed snapshot: country CIDRs are attributed to APNIC,
China domains to `felixonmars/dnsmasq-china-list`, and ad domains to older
curated lists. Force-tunnel domains are maintained in this repository and have
no single upstream feed. Built-in data does not refresh itself.

Run the source-aware updater to create external rule files:

```bash
python3 scripts/update_rule_data.py --output-dir /var/lib/rvpn/rules
```

It downloads AdGuard DNS filter (`filter_1.txt`), AdAway hosts via AdGuard
(`filter_2.txt`), the China domain list, and APNIC delegations. It converts
domain-only blocking rules and hosts entries to plain domain names, and APNIC
records to `country-ips.json`. China domain candidates still require an IP
match in the selected country's CIDRs before bypassing the VPN. APNIC records
describe allocation country, not guaranteed current server location. URL/regex
rules and exceptions that cannot be represented by domain matching are skipped.
`sources.json` records source URLs,
SHA-256 hashes, update time, and rule counts. Every output file is staged and
replaced atomically after download and minimum-count validation; a failed
update leaves the previous files in place.

Point `client.toml` at the generated files:

```toml
[split_tunnel]
enabled = true
block_ads = true
ad_block_file = "/var/lib/rvpn/rules/ad-domains.txt"
country_domains_file = "/var/lib/rvpn/rules/country-domains-cn.txt"
country_ips_file = "/var/lib/rvpn/rules/country-ips.json"
builtin_bypass_countries = ["CN"]
auto_reload_interval = 3600
```

`block_ads = false` disables ad blocking even when the file is present.
`auto_reload_interval` rereads the files; it does not download new versions.
For automatic upstream updates, run the same command daily with cron or a
systemd timer. For example, `0 3 * * * /usr/bin/python3 /opt/rvpn/scripts/update_rule_data.py --output-dir /var/lib/rvpn/rules`.
Run the updater once before enabling these file paths. If the country IP file
later becomes unavailable, the client falls back to its compiled-in CIDRs.

## Usage

### Generate keys

```bash
# Server identity key
cargo run --release --package rvpn-server -- keygen

# Server prekey bundle
cargo run --release --package rvpn-server -- prekey-bundle \
  --identity server_identity.key \
  --output prekey-bundle.json

# Client identity key
cargo run --release --package rvpn-client -- keygen --output identity.key
```

### Run the server

```bash
cargo run --release --package rvpn-server -- --config server.toml
```

### Run the client (SOCKS5 proxy mode)

```bash
cargo run --release --package rvpn-client -- --config client.toml
```

This starts a SOCKS5 proxy on `127.0.0.1:1080`. Configure your browser or system to use it.

### Run the client (TUN mode, requires root)

```bash
sudo cargo run --release --package rvpn-client -- --config client.toml --tun
```

## Releases

Pre-built binaries for all platforms are published as GitHub releases on this repository. The native apps (macOS, iOS, Android) are distributed through their respective app stores.

## Documentation

Full documentation is at [docs.rvpn.org](https://docs.rvpn.org). The whitepaper is at [rvpn.org](https://rvpn.org).

## Licensing

rVPN is dual-licensed:

- **AGPL-3.0** for open-source use
- **Commercial license** for proprietary use, SaaS providers, or when AGPL obligations cannot be met

See [LICENSE](LICENSE) and [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md).

Commercial licensing: license@pdg-global.com

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities privately to security@rvpn.org. See [SECURITY.md](SECURITY.md).

## About

PDG Global Limited (Hong Kong)

- Website: https://rvpn.org
- GitHub: https://github.com/PDG-Global/rVPN-core
