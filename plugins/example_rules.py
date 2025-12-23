from __future__ import annotations

from typing import List

from bs4 import BeautifulSoup

from phishlens.report import Finding
from phishlens.rules import Rule, RuleContext, finding


_KEYWORDS = {
    "verify your account",
    "account suspended",
    "unusual activity",
    "urgent",
    "confirm your identity",
}


def get_rules() -> List[Rule]:
    return [
        Rule(
            rule_id="SOCIAL_ENGINEERING_KEYWORDS",
            title="Social engineering keywords in page text",
            severity="medium",
            weight=10,
            check=_keywords_in_text,
        )
    ]


def _keywords_in_text(soup: BeautifulSoup, ctx: RuleContext) -> List[Finding]:
    text = " ".join(soup.stripped_strings).lower()
    hits = sorted(k for k in _KEYWORDS if k in text)

    if not hits:
        return []

    rule = get_rules()[0]
    return [
        finding(
            rule=rule,
            description="Phishing pages often use urgency/verification language to pressure users.",
            evidence={"hits": hits},
        )
    ]
