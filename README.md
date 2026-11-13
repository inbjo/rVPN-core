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

### Build artifacts and releases

Pushes and pull requests build client/server binaries and retain them as Actions
artifacts. Pushes, scheduled builds, and manual runs on `main` update a single `nightly`
tag and prerelease, replacing assets with the same names. After a successful
nightly upload, older generated `nightly-YYYYMMDD-RUN_ID` prereleases and their
tags are removed. Other version tags and releases are preserved.

Publishing a GitHub Release builds its tagged commit and uploads the matching
platform archives and checksums to that release. Rerunning the workflow replaces
same-name assets without creating another release or version tag.

Client archives and Actions artifacts include `client.toml.example`; server
archives and artifacts include `server.toml.example`. Copy the example to
`client.toml` or `server.toml` and adjust it before starting. The originals live
under `config/`, and changes there trigger a new build.

Each platform also uploads a separate `build-timings-*` Actions artifact with
Cargo's HTML compilation reports. Cache exact-match status appears in the job
summary. These diagnostics are separate from release archives.

Configuration tests use the `ci-test` profile, with optimization, debug symbols,
LTO, and incremental compilation disabled. Dependency caches retain both the
release and test profiles; the first run with a new cache key warms both sets.
To run the same checks locally:

```bash
cd rvpn
cargo test --profile ci-test --locked -p rvpn-client --bin rvpn config::tests
cargo test --profile ci-test --locked -p rvpn-server --lib config::tests
```

### Configuration paths

For both client and server on Windows, Linux, and macOS, relative `--config` / `-c` paths are resolved
from the executable's directory, independently of the terminal's current
directory. `client.toml` and `./client.toml` both refer to the file beside the
executable. Defaults are `client.toml` and `server.toml` in their respective executable directories. Absolute paths are
used directly.

Relative paths inside TOML/JSON configurations (identity keys, prekey bundles,
extra-server bundles, routing rules, known hosts, and an explicitly relative
`data_dir`) are resolved from the configuration file's directory. Both
`identity.key` and `./identity.key` work. For example:

```toml
identity_key_file = "./identity.key"
prekey_bundle = "./prekey-bundle.json"
```

The `--bundle` CLI override resolves relative to the executable's directory.
Missing configuration/key errors include the resolved file path.

The server uses the same configuration-directory rule for `tls_cert_file`,
`tls_key_file`, `identity_key_file`, `prekey_bundle_file`, `decoy_root`, and
`acme.cache_dir`. Both `[server]` sections and root-level TOML/JSON are supported.
For example:

```toml
[server]
tls_cert_file = "./certs/cert.pem"
tls_key_file = "./certs/key.pem"
identity_key_file = "./server_identity.key"
prekey_bundle_file = "./prekey-bundle.json"

[server.acme]
enabled = false
cache_dir = "./acme-cache"
```

Server `--identity`, `--rotate-from`, and explicit `--output` CLI overrides keep
their working-directory semantics. `keygen` and `prekey-bundle` can run without
a configuration; normal startup reports missing or invalid configurations.

### Client system service

The CLI supports systemd on Linux, Windows Service Control Manager, and a
system LaunchDaemon on macOS. Run these commands as root (Unix) or from an
administrator terminal (Windows):

```text
rvpn --config /absolute/path/client.toml service install
rvpn service start
rvpn service status
rvpn service stop
rvpn service uninstall
```

On Windows use a Windows path, for example
`rvpn.exe --config C:\rvpn\client.toml service install`.
Installation enables startup at boot; use `service start` to start immediately.
Linux requires systemd. Service names are `rvpn-client` (Linux/Windows) and
`com.rvpn.client` (macOS). Installation does not copy the executable, config,
or keys: keep them at their installed paths. Relative paths in the configuration
are resolved from the configuration file's directory for all three platforms.
Put runtime settings in the configuration file; service installation rejects CLI
overrides. Services run as root/LocalSystem, so set an explicit writable `data_dir`
and ensure the service account can read the identity key and prekey bundle.
Unix logs are available through `journalctl -u rvpn-client` (Linux) or
`/var/log/rvpn-client.log` (macOS).

### Client TLS trust

Desktop VPN connections load CA certificates from the Windows certificate
store, macOS Keychain, or Linux system CA bundle. BoringSSL still performs
certificate-chain and hostname verification and provides the Chrome TLS
fingerprint. No separate CA file is needed for certificates trusted by the OS.
The trust anchors are loaded once per process; restart the client after changing
system trust settings. `SSL_CERT_FILE` / `SSL_CERT_DIR`, when set, override the
system certificate source. An empty or unusable trust store causes a connection
error. DNS, SOCKS5, and HTTP proxy connection errors include the underlying error
chain so certificate failures remain visible.

### Client DNS over HTTPS

DNS upstreams are configured directly in `dns_proxy.nameservers`. Use an
IP address (optionally with a port) for UDP, or an HTTPS URL for DoH:

```toml
[dns_proxy]
enabled = true
listen_address = "127.0.0.1:53"
nameservers = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]
```

UDP and DoH entries can be mixed, for example
`nameservers = ["https://1.1.1.1/dns-query", "223.5.5.5:53"]`.
Upstreams are tried in configured order. To prevent plaintext fallback, list
only DoH URLs. No extra UDP resolver or system resolver is used when a list
containing DoH fails. DoH URLs must use IP addresses to avoid circular DNS
resolution when the system DNS points at this proxy. HTTPS certificate
validation stays enabled. Requests use wire format POST with HTTP/2 support,
a five-second timeout, no redirects, and no environment HTTP proxy.

These nameservers also serve client-side split-tunnel, direct connection, and
VPN endpoint lookups. A nonempty `network.dns_servers` overrides this list for
those lookups and accepts the same UDP/DoH syntax. Existing UDP-only resolver
behavior is preserved. No separate `[network.doh]` section is needed.

The optional local `[dns_proxy]` listener still accepts UDP queries from apps;
DoH changes its local upstream transport. Tunnel-routed A/AAAA queries keep
the existing encrypted WebSocket DNS path. In TUN mode, tunneled DNS packets
keep their existing forwarding path; this setting controls client-side lookups
and does not replace the remote server's resolver.

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
archives plus `SHA256SUMS.txt`, replacing the fixed `nightly` prerelease. It also rebuilds
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
The nightly client archives include the same generated files under `rules/`,
including source hashes and upstream license notices, plus `client.toml.example`.
Server archives contain the server executable, checksum, and `server.toml.example`.
Extracting a client archive under `/var/lib/rvpn`
provides the file paths used in the example above.
Run the updater once or extract a client archive before enabling these file
paths. If the country IP file later becomes unavailable, the client falls back
to its compiled-in CIDRs.

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
