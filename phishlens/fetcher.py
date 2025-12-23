from __future__ import annotations

from dataclasses import dataclass
import re
import urllib.request
from urllib.error import HTTPError, URLError


@dataclass(frozen=True)
class FetchResult:
    final_url: str
    status: int
    content_type: str
    html: str


def fetch_html(
    url: str,
    *,
    timeout_seconds: int = 12,
    max_bytes: int = 2_000_000,
    user_agent: str = "PhishLens/1.0 (offline analyzer)",
) -> FetchResult:
    if not url or not isinstance(url, str):
        raise ValueError("url must be a non-empty string")

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            status = getattr(resp, "status", 200)
            final_url = getattr(resp, "geturl", lambda: url)()
            content_type = resp.headers.get("Content-Type", "")

            raw = resp.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise ValueError(f"Response too large (> {max_bytes} bytes). Use a smaller max limit.")

            encoding = _encoding_from_content_type(content_type) or "utf-8"
            html = raw.decode(encoding, errors="replace")

            return FetchResult(final_url=final_url, status=int(status), content_type=content_type, html=html)

    except HTTPError as e:
        body = b""
        try:
            body = e.read(max_bytes)
        except Exception:
            body = b""
        content_type = getattr(e, "headers", {}).get("Content-Type", "") if getattr(e, "headers", None) else ""
        encoding = _encoding_from_content_type(content_type) or "utf-8"
        html = body.decode(encoding, errors="replace")
        return FetchResult(final_url=url, status=int(getattr(e, "code", 0) or 0), content_type=content_type, html=html)

    except URLError as e:
        raise ConnectionError(f"Failed to fetch URL: {url}. Reason: {e}")


def _encoding_from_content_type(content_type: str) -> str | None:
    if not content_type:
        return None
    m = re.search(r"charset=([^;\s]+)", content_type, flags=re.IGNORECASE)
    if not m:
        return None
    return m.group(1).strip('"').strip()
