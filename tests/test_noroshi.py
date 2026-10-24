import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from noroshi import __main__ as cli
from noroshi import notify_line, scoring
from noroshi.sources import nvd
from noroshi.matcher import Watchlist
from noroshi.models import Vuln

ROOT = Path(__file__).resolve().parent.parent


class MatcherTest(unittest.TestCase):
    def setUp(self):
        self.wl = Watchlist.load(ROOT / "config" / "watchlist.json")

    def test_cpe_wildcard(self):
        v = Vuln(id="X", cpes=["microsoft:windows_server_2022"])
        self.wl.match(v)
        self.assertEqual((v.matched, v.match_type, v.tier), (["windows"], "exact", 1))

    def test_php_file_extension_is_not_php(self):
        v = Vuln(id="X", description="SQL injection in admin/index.php of Acme CMS")
        self.wl.match(v)
        self.assertEqual(v.matched, [])

    def test_wordpress_plugin_excluded(self):
        v = Vuln(id="X", description="The Foo plugin for WordPress is vulnerable. PHP 8 affected.")
        self.wl.match(v)
        self.assertEqual(v.matched, [])

    def test_keyword_fallback_without_cpe(self):
        v = Vuln(id="X", description="A flaw in OpenSSH sshd before 10.2")
        self.wl.match(v)
        self.assertEqual((v.matched, v.match_type), (["openssh"], "keyword"))

    def test_package_match(self):
        v = Vuln(id="X", packages=["composer:laravel/framework"])
        self.wl.match(v)
        self.assertEqual(v.matched, ["laravel"])

    def test_unmatched_kev_is_kept(self):
        v = Vuln(id="X", kev=True, vendor_products=["Acme Router"])
        self.wl.match(v)
        self.assertEqual(v.match_type, "kev-only")


class ScoringTest(unittest.TestCase):
    def test_tier1_unauth_rce_alerts_without_kev_or_x(self):
        # KEV 掲載や X の反応より前でも、基盤ソフトの未認証 RCE は即時通知の水準に乗る
        v = Vuln(id="X", tier=1, match_type="exact", cvss=9.8,
                 cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                 description="allows remote code execution")
        scoring.score(v)
        self.assertEqual(v.level, "critical")

    def test_tier2_medium_cvss_is_not_critical(self):
        v = Vuln(id="X", tier=2, match_type="exact", cvss=6.1, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R")
        scoring.score(v)
        self.assertNotEqual(v.level, "critical")

    def test_score_capped(self):
        v = Vuln(id="X", tier=1, match_type="exact", cvss=10, kev=True, ransomware=True,
                 exploit_ref=True, epss=1.0, x_mentions=10 ** 6,
                 cvss_vector="AV:N/PR:N", description="remote code execution")
        scoring.score(v)
        self.assertEqual(v.score, 100)


class NvdParseTest(unittest.TestCase):
    def test_platform_cpes_are_ignored(self):
        item = {"cve": {"id": "CVE-X", "configurations": [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", "vulnerable": True},
            {"criteria": "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*", "vulnerable": False},
        ]}]}]}}
        self.assertEqual(nvd.parse(item).cpes, ["php:php"])


class NotifyTest(unittest.TestCase):
    def test_summary_uses_first_sentence_and_ellipsis(self):
        v = Vuln(id="X", description="PHP uses longjmp() for OOM errors. Second sentence.")
        self.assertEqual(notify_line.summary(v), "PHP uses longjmp() for OOM errors")
        v = Vuln(id="X", description="a" * 150)
        self.assertEqual(len(notify_line.summary(v)), 100)
        self.assertTrue(notify_line.summary(v).endswith("…"))


class EndToEndMockTest(unittest.TestCase):
    def run_cli(self, data_dir):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.main(["--mock", "--data-dir", data_dir])
        return out.getvalue()

    def test_mock_run(self):
        with tempfile.TemporaryDirectory() as d:
            out = self.run_cli(d)
            items = json.loads((Path(d) / "vulns.json").read_text())["items"]
            ids = {i["id"]: i for i in items}
            self.assertEqual(set(ids), {"CVE-2026-90001", "CVE-2026-90002", "CVE-2026-90005",
                                        "CVE-2026-90006", "CVE-2026-90007"})
            self.assertEqual(ids["CVE-2026-90001"]["sources"], ["nvd", "kev"])
            self.assertEqual({i for i, v in ids.items() if v["level"] == "critical"},
                             {"CVE-2026-90001", "CVE-2026-90006"})
            self.assertIn("ドライラン", out)
            self.assertNotIn("CVE-2021-44228", out)  # 古い KEV 掲載は新着扱いしない


if __name__ == "__main__":
    unittest.main()
