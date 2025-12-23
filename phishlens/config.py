from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Set


def load_allowlist(path: str | None) -> Set[str]:
    if not path:
        return set()

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Allowlist file not found: {p}")

    data = json.loads(p.read_text(encoding="utf-8"))
    domains: Iterable[str] = data.get("domains", []) if isinstance(data, dict) else data
    return {str(d).strip().lower() for d in domains if str(d).strip()}
