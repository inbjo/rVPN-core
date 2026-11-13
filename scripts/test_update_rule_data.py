import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import update_rule_data as rules


class RuleDataTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
