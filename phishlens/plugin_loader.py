from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Iterable, List

from .rules import Rule


def load_plugins(paths: Iterable[str | Path]) -> List[Rule]:
    rules: List[Rule] = []

    for p in paths:
        path = Path(p)
        if not path.exists():
            raise FileNotFoundError(f"Plugin not found: {path}")
        if not path.is_file():
            raise ValueError(f"Plugin path is not a file: {path}")

        mod = _load_module_from_path(path)
        rules.extend(_extract_rules(mod, path))

    return rules


def _load_module_from_path(path: Path) -> ModuleType:
    name = f"phishlens_plugin_{path.stem}"  # best-effort unique
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load plugin module: {path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _extract_rules(module: ModuleType, path: Path) -> List[Rule]:
    if hasattr(module, "get_rules"):
        out = module.get_rules()  # type: ignore[attr-defined]
        _validate_rules(out, path)
        return list(out)

    if hasattr(module, "RULES"):
        out = module.RULES  # type: ignore[attr-defined]
        _validate_rules(out, path)
        return list(out)

    raise AttributeError(f"Plugin must define get_rules() or RULES: {path}")


def _validate_rules(obj, path: Path) -> None:
    if not isinstance(obj, (list, tuple)):
        raise TypeError(f"Plugin rules must be a list/tuple of Rule: {path}")
    for r in obj:
        if not isinstance(r, Rule):
            raise TypeError(f"Plugin returned non-Rule item ({type(r)}): {path}")
