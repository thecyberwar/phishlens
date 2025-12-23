from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from bs4 import BeautifulSoup

from .report import Finding


@dataclass(frozen=True)
class RuleContext:
    target: str
    base_url: Optional[str]
    base_domain: str
    allowlist: set[str]
    resource_domains: Dict[str, int]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    weight: int
    check: Callable[[BeautifulSoup, RuleContext], List[Finding]]


def finding(*, rule: Rule, description: str, evidence: Dict[str, Any]) -> Finding:
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        weight=rule.weight,
        description=description,
        evidence=evidence,
    )
