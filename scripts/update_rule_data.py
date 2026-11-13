#!/usr/bin/env python3
"""Refresh rVPN's file-backed routing rules from their published sources."""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.request
from datetime import datetime, timezone


SOURCES = {
    "adguard_dns": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    "adaway": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt",
    "china_domains": "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf",
    "apnic": "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest",
}
COUNTRIES = ("CN", "HK", "SG", "JP", "KR", "TW")
DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
ADGUARD_DOMAIN = re.compile(r"\|\|([a-z0-9.-]+)\^\Z")
MAX_SOURCE_BYTES = 20 * 1024 * 1024


def fetch(url: str) -> bytes:
    # curl verifies Content-Length and retries interrupted transfers. It is
    # available on most desktop hosts; the urllib path below remains a fallback.
    if shutil.which("curl"):
        with tempfile.TemporaryDirectory(prefix="rvpn-fetch-") as stage:
            path = Path(stage) / "source"
            command = [
                "curl", "--fail", "--location", "--silent", "--show-error",
                "--proto", "=https", "--proto-redir", "=https",
                "--retry", "3", "--max-time", "90",
                "--max-filesize", str(MAX_SOURCE_BYTES),
                "--output", str(path), url,
            ]
            try:
                subprocess.run(command, check=True, capture_output=True, timeout=100)
                data = path.read_bytes()
                if not data or len(data) > MAX_SOURCE_BYTES:
                    raise ValueError(f"invalid source size: {url}")
                return data
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass

    headers = {"User-Agent": "rvpn-rule-updater/1", "Accept-Encoding": "identity"}
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        if not response.url.startswith("https://"):
            raise ValueError(f"source redirected away from HTTPS: {url}")
        expected = response.headers.get("Content-Length")
        etag = response.headers.get("ETag")
        chunks = []
        size = 0
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_SOURCE_BYTES:
                raise ValueError(f"source exceeds {MAX_SOURCE_BYTES} bytes: {url}")
            chunks.append(chunk)
    data = b"".join(chunks)
    if expected is not None:
        total = int(expected)
        if total > MAX_SOURCE_BYTES:
            raise ValueError(f"source exceeds {MAX_SOURCE_BYTES} bytes: {url}")
        # Some proxies close large responses early. Resume only when the origin
        # honors byte ranges and confirms the same ETag/total length.
        for _ in range(32):
            if len(data) >= total:
                break
            start = len(data)
            range_headers = {**headers, "Range": f"bytes={start}-"}
            if etag:
                range_headers["If-Range"] = etag
            request = urllib.request.Request(url, headers=range_headers)
            with urllib.request.urlopen(request, timeout=30) as response:
                if not response.url.startswith("https://"):
                    raise ValueError(f"source redirected away from HTTPS: {url}")
                content_range = response.headers.get("Content-Range", "")
                match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", content_range)
                if response.status != 206 or not match or (int(match[1]), int(match[3])) != (start, total):
                    raise ValueError(f"cannot safely resume download: {url}")
                chunks = []
                while chunk := response.read(1024 * 1024):
                    chunks.append(chunk)
                part = b"".join(chunks)
                if not part or len(data) + len(part) > total:
                    raise ValueError(f"invalid range response: {url}")
                data += part
        if len(data) != total:
            raise ValueError(f"incomplete download: {url} ({len(data)} of {total} bytes)")
    return data


def valid_domain(value: str) -> bool:
    value = value.rstrip(".").lower()
    return 1 < len(value) <= 253 and "." in value and all(
        DOMAIN_LABEL.fullmatch(label) for label in value.split(".")
    )


def parse_adguard_dns(text: str) -> set[str]:
    # DNS-level domain rules only. URL/regex/modifier and exception rules cannot
    # be represented by the client's domain matcher, so they are skipped.
    domains = set()
    for line in text.splitlines():
        match = ADGUARD_DOMAIN.fullmatch(line.strip().lower())
        if match and valid_domain(match.group(1)):
            domains.add(match.group(1))
    return domains


def parse_adaway_hosts(text: str) -> set[str]:
    domains = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0] not in {"127.0.0.1", "0.0.0.0", "::1"}:
            continue
        domains.update(name.lower() for name in fields[1:] if valid_domain(name))
    return domains


def parse_china_domains(text: str) -> set[str]:
    domains = set()
    for line in text.splitlines():
        if not line.startswith("server=/"):
            continue
        parts = line.split("/", 2)
        if len(parts) == 3 and valid_domain(parts[1]):
            domains.add(parts[1].lower())
    return domains


def parse_apnic(text: str) -> dict[str, list[str]]:
    result: dict[str, set[str]] = {country: set() for country in COUNTRIES}
    for line in text.splitlines():
        fields = line.split("|")
        if len(fields) < 7 or fields[0] != "apnic" or fields[1] not in result:
            continue
        country, family, address, value = fields[1:5]
        if fields[6] not in {"allocated", "assigned"}:
            continue
        try:
            if family == "ipv4":
                first = ipaddress.IPv4Address(address)
                count = int(value)
                if count <= 0:
                    continue
                last = ipaddress.IPv4Address(int(first) + count - 1)
                networks = ipaddress.summarize_address_range(first, last)
            elif family == "ipv6":
                networks = [ipaddress.IPv6Network(f"{address}/{int(value)}", strict=False)]
            else:
                continue
            result[country].update(str(network) for network in networks)
        except (ValueError, ipaddress.AddressValueError):
            continue
    return {
        country: sorted(networks, key=lambda cidr: (
            ipaddress.ip_network(cidr).version,
            int(ipaddress.ip_network(cidr).network_address),
            ipaddress.ip_network(cidr).prefixlen,
        ))
        for country, networks in result.items()
    }


def update(output_dir: Path) -> dict[str, int]:
    raw = {name: fetch(url) for name, url in SOURCES.items()}
    decoded = {name: data.decode("utf-8") for name, data in raw.items()}
    ad_domains = parse_adguard_dns(decoded["adguard_dns"])
    ad_domains.update(parse_adaway_hosts(decoded["adaway"]))
    china_domains = parse_china_domains(decoded["china_domains"])
    country_ips = parse_apnic(decoded["apnic"])

    # An upstream format change or a partial response must never replace good
    # rules with a nearly empty list.
    if len(ad_domains) < 50_000 or len(china_domains) < 50_000 or len(country_ips["CN"]) < 1_000:
        raise ValueError("upstream rules did not pass minimum-count validation")

    metadata = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "sources": {
            name: {"url": SOURCES[name], "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in raw.items()
        },
        "counts": {
            "ad_domains": len(ad_domains),
            "china_domains": len(china_domains),
            **{f"{country}_networks": len(networks) for country, networks in country_ips.items()},
        },
    }
    files = {
        "ad-domains.txt": "".join(f"{domain}\n" for domain in sorted(ad_domains)),
        "country-domains-cn.txt": "".join(f"{domain}\n" for domain in sorted(china_domains)),
        "country-ips.json": json.dumps(country_ips, separators=(",", ":")) + "\n",
        "sources.json": json.dumps(metadata, indent=2, sort_keys=True) + "\n",
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".rvpn-rules-", dir=output_dir) as stage:
        staged = Path(stage)
        for name, content in files.items():
            (staged / name).write_text(content, encoding="utf-8")
        for name in files:
            os.replace(staged / name, output_dir / name)
    return metadata["counts"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(update(args.output_dir), sort_keys=True))


if __name__ == "__main__":
    main()
