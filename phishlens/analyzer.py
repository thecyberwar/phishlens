from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from bs4 import BeautifulSoup

from .builtin_rules import get_builtin_rules
from .report import Finding, Report
from .rules import Rule, RuleContext
from .utils import get_domain


_RULE_MAX_CONTRIBUTION = {
    "JS_HIGH_ENTROPY_INLINE": 12,
    "JS_OBFUSCATION_APIS": 40,
    "JS_LOCALHOST_CALLS": 36,
}


def analyze_path(
    path: Path,
    *,
    base_url: Optional[str],
    allowlist: set[str],
    extra_rules: Optional[List[Rule]] = None,
) -> List[Report]:
    html_files: List[Path] = []

    if path.is_file():
        html_files = [path]
    elif path.is_dir():
        html_files = [p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in {".html", ".htm"}]

    reports: List[Report] = []
    for p in sorted(html_files):
        html = p.read_text(encoding="utf-8", errors="replace")
        reports.append(
            analyze_html(
                html,
                target=str(p),
                base_url=base_url,
                allowlist=allowlist,
                extra_rules=extra_rules,
            )
        )

    return reports


def analyze_html(
    html: str,
    *,
    target: str = "<memory>",
    base_url: Optional[str],
    allowlist: set[str],
    extra_rules: Optional[List[Rule]] = None,
) -> Report:
    soup = BeautifulSoup(html or "", "html.parser")

    base_domain = get_domain(base_url) if base_url else ""

    resource_domains = _collect_resource_domains(soup)

    ctx = RuleContext(
        target=target,
        base_url=base_url,
        base_domain=base_domain,
        allowlist=set(d.lower() for d in allowlist),
        resource_domains=resource_domains,
    )

    findings: List[Finding] = []
    rules: List[Rule] = []
    rules.extend(get_builtin_rules())
    if extra_rules:
        rules.extend(extra_rules)

    for rule in rules:
        try:
            findings.extend(rule.check(soup, ctx))
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="RULE_ERROR",
                    title=f"Rule error: {rule.rule_id}",
                    severity="low",
                    weight=1,
                    description=str(e),
                    evidence={"rule_id": rule.rule_id},
                )
            )

    score = _score_from_findings(findings)
    rating = _rating(score)

    stats = {
        "forms": len(soup.find_all("form")),
        "inputs": len(soup.find_all("input")),
        "scripts": len(soup.find_all("script")),
        "iframes": len(soup.find_all("iframe")),
        "resource_domains": resource_domains,
    }

    return Report(
        target=target,
        base_url=base_url,
        base_domain=base_domain,
        score=score,
        rating=rating,
        findings=sorted(findings, key=lambda f: f.weight, reverse=True),
        stats=stats,
    )


def _collect_resource_domains(soup: BeautifulSoup) -> Dict[str, int]:
    urls: List[str] = []

    for tag, attr in (
        ("script", "src"),
        ("link", "href"),
        ("img", "src"),
        ("iframe", "src"),
        ("form", "action"),
        ("a", "href"),
    ):
        for el in soup.find_all(tag):
            v = (el.get(attr) or "").strip()
            if v:
                urls.append(v)

    counts: Dict[str, int] = {}
    for u in urls:
        d = get_domain(u)
        if not d:
            continue
        counts[d] = counts.get(d, 0) + 1

    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))


def _score_from_findings(findings: List[Finding]) -> int:
    by_rule: Dict[str, List[Finding]] = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, []).append(f)

    total = 0
    for rule_id, items in by_rule.items():
        items_sorted = sorted(items, key=lambda x: x.weight, reverse=True)

        contrib = 0
        for idx, f in enumerate(items_sorted):
            w = max(0, f.weight)
            if idx == 0:
                contrib += w
            else:
                contrib += max(1, w // 2)

        cap = _RULE_MAX_CONTRIBUTION.get(rule_id)
        if cap is not None:
            contrib = min(cap, contrib)

        total += contrib

    return max(0, min(100, total))


def _rating(score: int) -> str:
    if score >= 80:
        return "high_risk"
    if score >= 45:
        return "medium_risk"
    return "low_risk"
