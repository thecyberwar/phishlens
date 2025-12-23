from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Dict, List


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    weight: int
    description: str
    evidence: Dict[str, Any]


@dataclass
class Report:
    target: str
    base_url: str | None
    base_domain: str
    score: int
    rating: str
    findings: List[Finding]
    stats: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "base_url": self.base_url,
            "base_domain": self.base_domain,
            "score": self.score,
            "rating": self.rating,
            "stats": self.stats,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "weight": f.weight,
                    "description": f.description,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    def to_html(self) -> str:
        esc = _html_escape
        items = "\n".join(
            f"<li><b>{esc(f.severity.upper())}</b> [{esc(f.rule_id)}] {esc(f.title)}<br/>"
            f"<pre>{esc(f.description)}</pre>"
            f"<pre>{esc(json.dumps(f.evidence, indent=2, ensure_ascii=False))}</pre></li>"
            for f in self.findings
        )
        return (
            "<!doctype html>"
            "<html><head><meta charset='utf-8'/>"
            "<title>PhishLens Report</title>"
            "<style>body{font-family:system-ui,Segoe UI,Arial;margin:24px}"
            ".score{font-size:20px;margin-bottom:12px}"
            "pre{background:#f6f8fa;padding:12px;border-radius:8px;overflow:auto}"
            "</style></head><body>"
            f"<h1>PhishLens Report</h1>"
            f"<div class='score'>Target: <code>{esc(self.target)}</code><br/>"
            f"Score: <b>{self.score}/100</b> &nbsp; Rating: <b>{esc(self.rating)}</b><br/>"
            f"Base domain: <code>{esc(self.base_domain or '-')}</code></div>"
            f"<h2>Findings ({len(self.findings)})</h2>"
            f"<ol>{items}</ol>"
            "</body></html>"
        )

    def write(self, out_dir: Path, fmt: str = "both") -> List[Path]:
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_name = _safe_filename(self.target)
        written: List[Path] = []

        if fmt in ("json", "both"):
            p = out_dir / f"{safe_name}.json"
            p.write_text(self.to_json(), encoding="utf-8")
            written.append(p)

        if fmt in ("html", "both"):
            p = out_dir / f"{safe_name}.html"
            p.write_text(self.to_html(), encoding="utf-8")
            written.append(p)

        return written


def _safe_filename(s: str) -> str:
    s = s.replace("\\", "_").replace("/", "_").replace(":", "_")
    return "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in s)[:120]


def _html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
