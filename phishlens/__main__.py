from __future__ import annotations

import argparse
import random
from pathlib import Path
from urllib.parse import urlparse

from .analyzer import analyze_path, analyze_html
from .config import load_allowlist
from .fetcher import fetch_html
from .plugin_loader import load_plugins


_BANNERS = {
    "b1": """██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗     ███████╗███╗   ██╗███████╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║██║     ██╔════╝████╗  ██║██╔════╝
██████╔╝███████║██║███████╗███████║██║     █████╗  ██╔██╗ ██║███████╗
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║     ██╔══╝  ██║╚██╗██║╚════██║
██║     ██║  ██║██║███████║██║  ██║███████╗███████╗██║ ╚████║███████║
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝""",
    "b2": """PHISHLENS
========
Detect fake login pages. Score. Explain. Report.""",
    "b3": """┌───────────────────────────┐
│         PHISHLENS          │
│   Phishing Page Detector   │
└───────────────────────────┘""",
    "b4": """██████  ██  ██  ██  █████  ██      ███████ ███    ██ ███████
██   ██ ██  ██  ██ ██   ██ ██      ██      ████   ██ ██     
██████  ███████ ██ ███████ ██      █████   ██ ██  ██ ███████
██      ██  ██  ██ ██   ██ ██      ██      ██  ██ ██      ██
██      ██  ██  ██ ██   ██ ███████ ███████ ██   ████ ███████""",
    "b5": """[ PhishLens ]
> static HTML phishing detection
> scoring + findings + reports""",
    "b6": """███████╗██╗  ██╗██╗███████╗██╗  ██╗██╗     ███████╗███╗   ██╗███████╗
██╔════╝██║  ██║██║██╔════╝██║  ██║██║     ██╔════╝████╗  ██║██╔════╝
█████╗  ███████║██║███████╗███████║██║     █████╗  ██╔██╗ ██║███████╗
██╔══╝  ██╔══██║██║╚════██║██╔══██║██║     ██╔══╝  ██║╚██╗██║╚════██║
██║     ██║  ██║██║███████║██║  ██║███████╗███████╗██║ ╚████║███████║""",
    "b7": """╔═╗┬ ┬┬┌─┐┬ ┬┬  ┌─┐┌┐┌┌─┐
╠═╝├─┤│└─┐├─┤│  ├┤ │││└─┐
╩  ┴ ┴┴└─┘┴ ┴┴─┘└─┘┘└┘└─┘""",
    "b8": """PHISHLENS :: scan → score → explain → report""",
    "b9": """╭─────────────────────────────╮
│  PhishLens - Security Tool │
│  Fake Login Page Detector  │
╰─────────────────────────────╯""",
    "b10": """██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗     ███████╗███╗   ██╗███████╗
██████╔╝███████║██║███████╗███████║██║     █████╗  ██╔██╗ ██║███████╗
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║     ██╔══╝  ██║╚██╗██║╚════██║
██║     ██║  ██║██║███████║██║  ██║███████╗███████╗██║ ╚████║███████║""",
}


def _resolve_banner(banner: str) -> str:
    banner = (banner or "").strip().lower()
    if banner in {"none", "off", "0"}:
        return ""
    if banner in {"random", "rand"}:
        return _BANNERS[random.choice(sorted(_BANNERS.keys()))]
    if banner in _BANNERS:
        return _BANNERS[banner]
    return ""


def _print_banner(banner: str) -> None:
    text = _resolve_banner(banner)
    if not text:
        return
    try:
        from rich.console import Console
        from rich.text import Text
    except Exception:
        print(text)
        return

    console = Console()
    console.print(Text(text, style="bold cyan"))


def _print_report(*, report, written, fetch_status=None) -> None:
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
    except Exception:
        if fetch_status is None:
            print(f"{report.target}: score={report.score}/100 rating={report.rating} findings={len(report.findings)}")
        else:
            print(
                f"{report.target}: status={fetch_status} score={report.score}/100 rating={report.rating} findings={len(report.findings)}"
            )
        for p in written:
            print(f"  wrote: {p}")
        return

    console = Console()
    rating_style = {
        "low_risk": "green",
        "medium_risk": "yellow",
        "high_risk": "red",
    }.get(report.rating, "white")
    score_style = "green" if report.score < 25 else ("yellow" if report.score < 60 else "red")

    header = Text(str(report.target), style="bold")
    sub = Text.assemble(
        ("score ", "dim"),
        (f"{report.score}/100", score_style + " bold"),
        ("  |  ", "dim"),
        ("rating ", "dim"),
        (str(report.rating), rating_style + " bold"),
    )
    if fetch_status is not None:
        sub.append("  |  ", style="dim")
        sub.append("status ", style="dim")
        sub.append(str(fetch_status), style="bold")

    meta = Text.assemble(
        ("base_domain ", "dim"),
        (str(getattr(report, "base_domain", "-")), "bold"),
        ("  |  ", "dim"),
        ("findings ", "dim"),
        (str(len(report.findings)), "bold"),
    )

    console.print(Panel.fit(Text.assemble(header, "\n", sub, "\n", meta), border_style=score_style))

    if report.findings:
        table = Table(show_header=True, header_style="bold", show_lines=False)
        table.add_column("Severity", style="bold")
        table.add_column("Rule")
        table.add_column("Title")
        table.add_column("Wt", justify="right")

        sev_style = {
            "low": "green",
            "medium": "yellow",
            "high": "red",
        }

        for f in report.findings[:12]:
            s = str(getattr(f, "severity", ""))
            table.add_row(
                Text(s.upper(), style=sev_style.get(s, "white")),
                str(getattr(f, "rule_id", "")),
                str(getattr(f, "title", "")),
                str(getattr(f, "weight", "")),
            )
        if len(report.findings) > 12:
            table.add_row("…", "…", f"(+{len(report.findings) - 12} more)", "")
        console.print(table)

    if written:
        out_table = Table(show_header=True, header_style="bold")
        out_table.add_column("Report Files")
        for p in written:
            out_table.add_row(str(p))
        console.print(out_table)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishlens", description="Local fake-login page detector")
    parser.add_argument(
        "--banner",
        default="random",
        choices=("random", "none", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "b10"),
        help="Banner style (default: random). Use 'none' to disable.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Scan an HTML file or directory")
    scan.add_argument("input", help="Path to an HTML file or a directory containing HTML files")
    scan.add_argument("--base-url", default=None, help="Base URL used for domain comparisons (e.g. https://accounts.example.com)")
    scan.add_argument(
        "--allowlist",
        default=None,
        help="Path to allowlist JSON (e.g. allow trusted domains to reduce false positives)",
    )
    scan.add_argument(
        "--out-dir",
        default="reports",
        help="Directory where reports will be written (default: reports)",
    )
    scan.add_argument(
        "--format",
        default="both",
        choices=("json", "html", "both"),
        help="Report format to write",
    )
    scan.add_argument(
        "--plugin",
        action="append",
        default=[],
        help="Path to a Python plugin defining RULES or get_rules() (can be provided multiple times)",
    )

    scan_url = sub.add_parser("scan-url", help="Fetch a URL (HTML) and scan it")
    scan_url.add_argument("url", help="URL to fetch and analyze (do NOT enter credentials)")
    scan_url.add_argument(
        "--base-url",
        default=None,
        help="Base URL used for domain comparisons (default: derived from fetched URL)",
    )
    scan_url.add_argument(
        "--allowlist",
        default=None,
        help="Path to allowlist JSON (e.g. allow trusted domains to reduce false positives)",
    )
    scan_url.add_argument(
        "--out-dir",
        default="reports",
        help="Directory where reports will be written (default: reports)",
    )
    scan_url.add_argument(
        "--format",
        default="both",
        choices=("json", "html", "both"),
        help="Report format to write",
    )
    scan_url.add_argument(
        "--plugin",
        action="append",
        default=[],
        help="Path to a Python plugin defining RULES or get_rules() (can be provided multiple times)",
    )
    scan_url.add_argument("--timeout", type=int, default=12, help="Fetch timeout in seconds")
    scan_url.add_argument("--max-bytes", type=int, default=2_000_000, help="Max bytes to download")
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    _print_banner(args.banner)

    if args.cmd == "scan":
        allowlist = load_allowlist(args.allowlist)
        out_dir = Path(args.out_dir)
        extra_rules = load_plugins(args.plugin) if args.plugin else None

        results = analyze_path(
            Path(args.input),
            base_url=args.base_url,
            allowlist=allowlist,
            extra_rules=extra_rules,
        )
        if not results:
            print("No HTML files found.")
            return 2

        for report in results:
            written = report.write(out_dir=out_dir, fmt=args.format)
            _print_report(report=report, written=written)

        return 0

    if args.cmd == "scan-url":
        allowlist = load_allowlist(args.allowlist)
        out_dir = Path(args.out_dir)
        extra_rules = load_plugins(args.plugin) if args.plugin else None

        fetched = fetch_html(args.url, timeout_seconds=args.timeout, max_bytes=args.max_bytes)

        base_url = args.base_url
        if base_url is None:
            parsed = urlparse(fetched.final_url)
            if parsed.scheme and parsed.netloc:
                base_url = f"{parsed.scheme}://{parsed.netloc}"
            else:
                base_url = fetched.final_url

        rep = analyze_html(
            fetched.html,
            target=fetched.final_url,
            base_url=base_url,
            allowlist=allowlist,
            extra_rules=extra_rules,
        )
        rep.stats.update(
            {
                "fetch_status": fetched.status,
                "fetch_content_type": fetched.content_type,
                "fetch_final_url": fetched.final_url,
            }
        )
        written = rep.write(out_dir=out_dir, fmt=args.format)
        _print_report(report=rep, written=written, fetch_status=fetched.status)
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
