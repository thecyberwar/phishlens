from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from .report import Finding
from .rules import Rule, RuleContext, finding
from .utils import get_domain, is_allowlisted, is_ip_domain, shannon_entropy, subdomain_depth


_SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq"}


def get_builtin_rules() -> List[Rule]:
    return [
        Rule(
            rule_id="FORM_ACTION_EXTERNAL",
            title="Form posts to external domain",
            severity="high",
            weight=25,
            check=_form_action_external,
        ),
        Rule(
            rule_id="FORM_ACTION_INSECURE_HTTP",
            title="Form action uses insecure HTTP",
            severity="high",
            weight=20,
            check=_form_action_http,
        ),
        Rule(
            rule_id="EXTERNAL_JS_MIXED_DOMAINS",
            title="External JS from mixed/unknown domains",
            severity="medium",
            weight=12,
            check=_external_js_domains,
        ),
        Rule(
            rule_id="META_REFRESH_REDIRECT",
            title="Meta refresh redirect",
            severity="medium",
            weight=10,
            check=_meta_refresh,
        ),
        Rule(
            rule_id="SUSPICIOUS_HIDDEN_INPUTS",
            title="Suspicious hidden inputs",
            severity="low",
            weight=6,
            check=_hidden_inputs,
        ),
        Rule(
            rule_id="JS_OBFUSCATION_APIS",
            title="Inline JS contains obfuscation APIs (eval/atob/fromCharCode/etc.)",
            severity="high",
            weight=20,
            check=_js_obfuscation_apis,
        ),
        Rule(
            rule_id="JS_HIGH_ENTROPY_INLINE",
            title="High-entropy inline JavaScript (often minified)",
            severity="low",
            weight=6,
            check=_js_high_entropy_inline,
        ),
        Rule(
            rule_id="JS_LOCALHOST_CALLS",
            title="Inline JS calls localhost/private IP endpoints",
            severity="high",
            weight=18,
            check=_js_localhost_calls,
        ),
        Rule(
            rule_id="SUSPICIOUS_DOMAIN_PATTERN",
            title="Suspicious domain patterns (IP/punycode/deep subdomains/risky TLD)",
            severity="high",
            weight=22,
            check=_suspicious_domain_patterns,
        ),
        Rule(
            rule_id="IFRAME_HIDDEN",
            title="Hidden iframe present",
            severity="medium",
            weight=12,
            check=_hidden_iframe,
        ),
    ]


def _form_action_external(soup: BeautifulSoup, ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    rule = next(r for r in get_builtin_rules() if r.rule_id == "FORM_ACTION_EXTERNAL")

    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        method = (form.get("method") or "get").strip().lower()
        action_domain = get_domain(action)

        if not action:
            continue

        if action_domain and ctx.base_domain and action_domain != ctx.base_domain:
            if is_allowlisted(action_domain, ctx.allowlist):
                continue
            out.append(
                finding(
                    rule=rule,
                    description="A login form submitting to a different domain is a common phishing indicator.",
                    evidence={"action": action, "method": method, "action_domain": action_domain, "base_domain": ctx.base_domain},
                )
            )

    return out


def _form_action_http(soup: BeautifulSoup, ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    rule = next(r for r in get_builtin_rules() if r.rule_id == "FORM_ACTION_INSECURE_HTTP")

    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip().lower()
        if action.startswith("http://"):
            out.append(
                finding(
                    rule=rule,
                    description="Submitting credentials over HTTP is insecure and unusual for legitimate login pages.",
                    evidence={"action": action},
                )
            )

    return out


def _external_js_domains(soup: BeautifulSoup, ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    rule = next(r for r in get_builtin_rules() if r.rule_id == "EXTERNAL_JS_MIXED_DOMAINS")

    domains = set()
    for s in soup.find_all("script"):
        src = (s.get("src") or "").strip()
        if not src:
            continue
        d = get_domain(src)
        if d:
            domains.add(d)

    domains = {d for d in domains if not is_allowlisted(d, ctx.allowlist)}

    if ctx.base_domain:
        suspicious = {d for d in domains if d != ctx.base_domain}
    else:
        suspicious = set(domains)

    if suspicious:
        out.append(
            finding(
                rule=rule,
                description="Loading credential pages with external scripts from unrelated domains increases risk (skimming, injection, phishing kits).",
                evidence={"external_script_domains": sorted(suspicious), "base_domain": ctx.base_domain},
            )
        )

    return out


def _meta_refresh(soup: BeautifulSoup, ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    rule = next(r for r in get_builtin_rules() if r.rule_id == "META_REFRESH_REDIRECT")

    for meta in soup.find_all("meta"):
        http_equiv = (meta.get("http-equiv") or "").strip().lower()
        content = (meta.get("content") or "").strip()
        if http_equiv == "refresh" and "url=" in content.lower():
            # Flag only external redirects. Internal/relative refreshes are common on legitimate sites.
            parts = re.split(r"url=", content, flags=re.IGNORECASE, maxsplit=1)
            redirect = parts[1].strip().strip('"').strip("'") if len(parts) == 2 else ""

            # Relative URLs (e.g. /path) or bare paths are considered internal.
            parsed = urlparse(redirect)
            redirect_domain = get_domain(redirect)
            if not parsed.scheme and not parsed.netloc:
                continue
            if redirect_domain and ctx.base_domain and redirect_domain == ctx.base_domain:
                continue
            if redirect_domain and is_allowlisted(redirect_domain, ctx.allowlist):
                continue

            out.append(
                finding(
                    rule=rule,
                    description="Meta refresh redirects to an external domain can be used in phishing to forward victims.",
                    evidence={
                        "content": content,
                        "redirect": redirect,
                        "redirect_domain": redirect_domain,
                        "base_domain": ctx.base_domain,
                    },
                )
            )

    return out


def _hidden_inputs(soup: BeautifulSoup, ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    rule = next(r for r in get_builtin_rules() if r.rule_id == "SUSPICIOUS_HIDDEN_INPUTS")

    keywords = {"token", "session", "auth", "redirect", "return", "next", "url"}

    for i in soup.find_all("input"):
        t = (i.get("type") or "").strip().lower()
        if t != "hidden":
            continue
        name = (i.get("name") or i.get("id") or "").strip().lower()
        val = (i.get("value") or "").strip()
        if not name:
            continue
        if any(k in name for k in keywords) and len(val) > 120:
            out.append(
                finding(
                    rule=rule,
                    description="Large hidden tokens/redirect parameters can be abused to exfiltrate or redirect.",
                    evidence={"name": name, "value_len": len(val)},
                )
            )

    return out


def _js_obfuscation_apis(soup: BeautifulSoup, ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    rule = next(r for r in get_builtin_rules() if r.rule_id == "JS_OBFUSCATION_APIS")

    patterns = [
        r"\beval\s*\(",
        r"\batob\s*\(",
        r"fromCharCode\s*\(",
        r"document\.write\s*\(",
        r"new\s+Function\s*\(",
        r"\bunescape\s*\(",
    ]

    for s in soup.find_all("script"):
        if s.get("src"):
            continue
        text = (s.get_text() or "").strip()
        if len(text) < 80:
            continue

        hits = [p for p in patterns if re.search(p, text, re.IGNORECASE)]
        if not hits:
            continue

        out.append(
            finding(
                rule=rule,
                description="Inline JavaScript uses APIs commonly seen in obfuscated/phishing kit payloads.",
                evidence={"pattern_hits": hits, "snippet": text[:220]},
            )
        )

    return out


def _js_high_entropy_inline(soup: BeautifulSoup, ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    rule = next(r for r in get_builtin_rules() if r.rule_id == "JS_HIGH_ENTROPY_INLINE")

    for s in soup.find_all("script"):
        if s.get("src"):
            continue
        text = (s.get_text() or "").strip()
        if len(text) < 300:
            continue

        ent = shannon_entropy(text[:4000])
        # Higher threshold to avoid flagging normal minification on large legitimate sites.
        if ent < 5.2:
            continue

        out.append(
            finding(
                rule=rule,
                description="High-entropy inline JS can indicate heavy minification or obfuscation. Use together with other signals.",
                evidence={"entropy": round(ent, 3), "snippet": text[:220]},
            )
        )

    return out


def _js_localhost_calls(soup: BeautifulSoup, ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    rule = next(r for r in get_builtin_rules() if r.rule_id == "JS_LOCALHOST_CALLS")

    localhost_patterns = [
        r"https?://localhost(?::\d+)?",
        r"https?://127\.0\.0\.1(?::\d+)?",
        r"https?://\[::1\](?::\d+)?",
        r"https?://10\.(?:\d{1,3}\.){2}\d{1,3}(?::\d+)?",
        r"https?://192\.168\.(?:\d{1,3}\.)\d{1,3}(?::\d+)?",
        r"https?://172\.(?:1[6-9]|2\d|3[0-1])\.(?:\d{1,3}\.)\d{1,3}(?::\d+)?",
    ]

    for s in soup.find_all("script"):
        if s.get("src"):
            continue
        text = (s.get_text() or "").strip()
        if len(text) < 80:
            continue

        hits = [p for p in localhost_patterns if re.search(p, text, re.IGNORECASE)]
        if not hits:
            continue

        out.append(
            finding(
                rule=rule,
                description="Credential phishing kits sometimes call localhost/private endpoints to fingerprint devices or steal data.",
                evidence={"pattern_hits": hits, "snippet": text[:260]},
            )
        )

    return out


def _suspicious_domain_patterns(soup: BeautifulSoup, ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    rule = next(r for r in get_builtin_rules() if r.rule_id == "SUSPICIOUS_DOMAIN_PATTERN")

    domains = set(ctx.resource_domains.keys())
    if ctx.base_domain:
        domains.add(ctx.base_domain)

    suspicious = []
    for d in sorted(domains):
        if not d or is_allowlisted(d, ctx.allowlist):
            continue
        reasons = []
        if is_ip_domain(d):
            reasons.append("ip_domain")
        if d.startswith("xn--"):
            reasons.append("punycode")
        if subdomain_depth(d) >= 3:
            reasons.append("deep_subdomain")
        tld = d.split(".")[-1]
        if tld in _SUSPICIOUS_TLDS:
            reasons.append("risky_tld")
        if reasons:
            suspicious.append({"domain": d, "reasons": reasons})

    if suspicious:
        out.append(
            finding(
                rule=rule,
                description="Domain patterns often seen in phishing infrastructure (not definitive, but strong signals when combined).",
                evidence={"suspicious_domains": suspicious},
            )
        )

    return out


def _hidden_iframe(soup: BeautifulSoup, ctx: RuleContext) -> List[Finding]:
    out: List[Finding] = []
    rule = next(r for r in get_builtin_rules() if r.rule_id == "IFRAME_HIDDEN")

    for fr in soup.find_all("iframe"):
        style = (fr.get("style") or "").lower()
        width = (fr.get("width") or "").strip()
        height = (fr.get("height") or "").strip()
        if "display:none" in style or "visibility:hidden" in style or width in {"0", "1"} or height in {"0", "1"}:
            out.append(
                finding(
                    rule=rule,
                    description="Hidden iframes can be used for covert redirects or loading phishing kit components.",
                    evidence={"style": fr.get("style"), "width": width, "height": height, "src": fr.get("src")},
                )
            )

    return out
