import unittest
from pathlib import Path

from phishlens.analyzer import analyze_path
from phishlens.plugin_loader import load_plugins


class TestPhishLens(unittest.TestCase):
    def test_phish_scores_higher_than_legit(self):
        base_url = "https://accounts.example.com"
        allowlist = {"accounts.example.com"}
        extra_rules = load_plugins(["plugins/example_rules.py"])

        reports = analyze_path(Path("samples"), base_url=base_url, allowlist=allowlist, extra_rules=extra_rules)
        by_name = {Path(r.target).name: r for r in reports}

        self.assertIn("legit_like.html", by_name)
        self.assertIn("phish_like.html", by_name)

        legit = by_name["legit_like.html"]
        phish = by_name["phish_like.html"]

        self.assertLess(legit.score, phish.score)
        self.assertEqual(phish.rating, "high_risk")

    def test_plugin_rule_finds_keywords(self):
        base_url = "https://accounts.example.com"
        allowlist = {"accounts.example.com"}
        extra_rules = load_plugins(["plugins/example_rules.py"])

        report = analyze_path(
            Path("samples/phish_like.html"),
            base_url=base_url,
            allowlist=allowlist,
            extra_rules=extra_rules,
        )[0]
        self.assertTrue(any(f.rule_id == "SOCIAL_ENGINEERING_KEYWORDS" for f in report.findings))


if __name__ == "__main__":
    unittest.main()
