import tempfile
import base64
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import update_rule_data as rules


class RuleDataTests(unittest.TestCase):
    def test_gfwlist_base64_plaintext_and_exceptions(self):
        source = "[AutoProxy 0.2.9]\n||Example.COM\n.plain.org\n@@||safe.example.com\n|https://path.example/foo\n/regex/\n||wild*.example.com\n"
        expected = {"proxy": ["example.com", "plain.org"], "exceptions": ["safe.example.com"], "skipped": 3}
        self.assertEqual(rules.parse_gfwlist(source), expected)
        self.assertEqual(rules.parse_gfwlist(base64.b64encode(source.encode()).decode()), expected)
        for invalid in ["", "<html>error</html>", "! empty\n/regex/"]:
            with self.assertRaises(ValueError):
                rules.parse_gfwlist(invalid)

    def test_gfwlist_export_does_not_expand_child_exceptions(self):
        source = "! fixture\n" + "\n".join(f"||site{i}.example" for i in range(1100))
        source += "\n@@||safe.site1.example\n||child.safe.site1.example\n"
        files = rules.gfwlist_files(source.encode())
        parsed = json.loads(files["gfwlist-rules.json"])
        self.assertIn("site1.example", parsed["proxy"])
        self.assertIn("safe.site1.example", parsed["exceptions"])
        exported = set(files["gfwlist-domains.txt"].splitlines())
        self.assertNotIn("site1.example", exported)
        self.assertNotIn("child.safe.site1.example", exported)
        self.assertIn("site2.example", exported)
        self.assertIn("sha256", json.loads(files["gfwlist-source.json"]))

    def test_gfwlist_embedded_snapshot_matches_its_distributed_source(self):
        directory = Path(__file__).resolve().parents[1] / "rvpn/crates/rvpn-split-tunnel/data"
        raw = (directory / "gfwlist.txt").read_bytes()
        parsed = rules.parse_gfwlist(raw.decode("utf-8"))
        self.assertEqual(parsed, json.loads((directory / "gfwlist-rules.json").read_text()))
        source = json.loads((directory / "gfwlist-source.json").read_text())
        self.assertEqual(source["sha256"], rules.hashlib.sha256(raw).hexdigest())
        self.assertEqual(source["counts"]["proxy"], len(parsed["proxy"]))
        self.assertTrue((directory / "LICENSE-GFWList.txt").is_file())

    def test_adguard_domain_rules_skip_url_rules_and_exceptions(self):
        source = "\n".join([
            "! header",
            "||Ads.Example.COM^",
            "||tracker.example.net^$important",
            "@@||allowed.example.org^",
            "/example[0-9]/",
        ])
        self.assertEqual(rules.parse_adguard_dns(source), {"ads.example.com"})

    def test_adaway_hosts_only_accept_loopback_entries(self):
        source = "127.0.0.1 ads.example.com tracker.example.net\n0.0.0.0 metrics.example.org\n8.8.8.8 safe.example.com\n"
        self.assertEqual(
            rules.parse_adaway_hosts(source),
            {"ads.example.com", "tracker.example.net", "metrics.example.org"},
        )

    def test_china_domains_and_apnic_cidrs(self):
        self.assertEqual(
            rules.parse_china_domains("server=/example.cn/114.114.114.114\nserver=/bad host/1.1.1.1\n"),
            {"example.cn"},
        )
        source = "\n".join([
            "apnic|CN|ipv4|192.0.2.0|8|20261113|allocated",
            "apnic|HK|ipv6|2001:db8::|32|20261113|assigned",
            "apnic|US|ipv4|198.51.100.0|256|20261113|allocated",
        ])
        networks = rules.parse_apnic(source)
        self.assertEqual(networks["CN"], ["192.0.2.0/29"])
        self.assertEqual(networks["HK"], ["2001:db8::/32"])
        self.assertEqual(networks["JP"], [])

    def test_failed_fetch_keeps_previous_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            previous = output / "ad-domains.txt"
            previous.write_text("old.example\n")
            with patch.object(rules, "fetch", side_effect=OSError("offline")):
                with self.assertRaises(OSError):
                    rules.update(output)
            self.assertEqual(previous.read_text(), "old.example\n")

    def test_rule_bundle_includes_gfwlist_source_transforms_license_and_metadata(self):
        gfw = "! fixture\n" + "\n".join(f"||site{i}.example" for i in range(1100))
        def fetch(url):
            return gfw.encode() if url == rules.SOURCES["gfwlist"] else b"fixture"
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(rules, "fetch", side_effect=fetch), \
             patch.object(rules, "parse_adguard_dns", return_value={f"ad{i}.example" for i in range(50001)}), \
             patch.object(rules, "parse_adaway_hosts", return_value=set()), \
             patch.object(rules, "parse_china_domains", return_value={f"site{i}.cn" for i in range(50001)}), \
             patch.object(rules, "parse_apnic", return_value={"CN": ["1.0.0.0/24"] * 1001}):
            output = Path(tmp)
            counts = rules.update(output)
            self.assertEqual(counts["gfwlist_proxy"], 1100)
            for name in ["gfwlist.txt", "gfwlist-rules.json", "gfwlist-domains.txt", "gfwlist-source.json", "LICENSE-GFWList.txt"]:
                self.assertTrue((output / name).is_file(), name)
            manifest = json.loads((output / "sources.json").read_text())
            self.assertEqual(manifest["sources"]["gfwlist"]["url"], rules.SOURCES["gfwlist"])
            self.assertIn("LICENSE-GFWList.txt", manifest["licenses"])
            self.assertIn("LGPL-2.1", (output / "NOTICE.txt").read_text())


if __name__ == "__main__":
    unittest.main()
