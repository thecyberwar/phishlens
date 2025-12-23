from __future__ import annotations

import math
import re
from urllib.parse import urlparse


_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def safe_urlparse(url: str):
    try:
        return urlparse(url)
    except Exception:
        return urlparse("")


def get_domain(url: str) -> str:
    parsed = safe_urlparse(url)
    netloc = (parsed.netloc or "").strip().lower()
    if not netloc:
        return ""
    if "@" in netloc:
        netloc = netloc.split("@", 1)[-1]
    if ":" in netloc:
        netloc = netloc.split(":", 1)[0]
    return netloc


def is_ip_domain(domain: str) -> bool:
    return bool(_IP_RE.match(domain.strip().lower()))


def subdomain_depth(domain: str) -> int:
    parts = [p for p in domain.split(".") if p]
    if len(parts) <= 2:
        return 0
    return len(parts) - 2


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    for count in freq.values():
        p = count / len(s)
        ent -= p * math.log2(p)
    return ent


def is_allowlisted(domain: str, allowlist: set[str]) -> bool:
    d = (domain or "").strip().lower()
    if not d:
        return False

    if d in allowlist:
        return True

    for item in allowlist:
        v = (item or "").strip().lower()
        if not v:
            continue

        if v.startswith("*."):
            suffix = v[2:]
            if not suffix:
                continue
            if d == suffix or d.endswith("." + suffix):
                return True

    return False
