"""Classify license strings (SPDX expressions or free text) and sniff LICENSE files."""

from __future__ import annotations

import json
import re
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any

from absolutely_proprietary.models import Status

LICENSE_FILE_NAMES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "LICENCE.md", "COPYING", "COPYING.md")

_SUFFIXES = re.compile(r"(-only|-or-later|\+)$", re.IGNORECASE)
_OR = re.compile(r"\s+or\s+|\s*\|\|?\s*|\s*/\s*", re.IGNORECASE)
_AND = re.compile(r"\s+and\s+|\s*&&?\s*", re.IGNORECASE)
_OTHER_PROPRIETARY = re.compile(r"other\s*/\s*proprietary", re.IGNORECASE)
_WITH = re.compile(r"\s+with\s+.*$", re.IGNORECASE)
# Python trove classifiers: "License :: OSI Approved :: MIT License"
_CLASSIFIER_PREFIX = re.compile(r"^license\s*::\s*(osi approved\s*::\s*)?", re.IGNORECASE)


@cache
def _data() -> dict[str, Any]:
    text = resources.files("absolutely_proprietary.data").joinpath("licenses.json").read_text(encoding="utf-8")
    data: dict[str, Any] = json.loads(text)
    return data


@cache
def _free_ids() -> frozenset[str]:
    return frozenset(_SUFFIXES.sub("", i).lower() for i in _data()["free_spdx"])


def _keyword_pattern(words: tuple[str, ...]) -> re.Pattern[str]:
    # Left boundary only, so "gpl" matches "gplv3" but not "lgpl" and "mit" not "permitted".
    return re.compile("|".join(rf"(?<![a-z0-9]){re.escape(w)}" for w in words))


@cache
def _nonfree_re() -> re.Pattern[str]:
    return _keyword_pattern(tuple(_data()["nonfree_keywords"]))


@cache
def _free_re() -> re.Pattern[str]:
    return _keyword_pattern(tuple(_data()["free_keywords"]))


def _classify_leaf(term: str) -> Status:
    term = _WITH.sub("", term.strip().strip("()[]\"'").strip())
    term = _CLASSIFIER_PREFIX.sub("", term)
    lowered = term.lower()
    if not lowered or lowered in _data()["unknown_markers"]:
        return Status.UNKNOWN
    if _nonfree_re().search(lowered):
        return Status.NONFREE
    if _SUFFIXES.sub("", lowered) in _free_ids():
        return Status.FREE
    if _free_re().search(lowered):
        return Status.FREE
    return Status.UNKNOWN


def _split_top_level(expr: str, sep: re.Pattern[str]) -> list[str]:
    """Split on ``sep`` only where we're not inside parentheses."""
    parts: list[str] = []
    depth = start = 0
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0:
            match = sep.match(expr, i)
            if match and match.end() > i:
                parts.append(expr[start:i])
                start = i = match.end()
                continue
        i += 1
    parts.append(expr[start:])
    return [p for p in (s.strip() for s in parts) if p]


def _wraps_whole(expr: str) -> bool:
    """True for "(A OR B)", false for "(A) AND (B)"."""
    if not (expr.startswith("(") and expr.endswith(")")):
        return False
    depth = 0
    for i, ch in enumerate(expr):
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0 and i < len(expr) - 1:
            return False
    return True


def _strip_parens(expr: str) -> str:
    expr = expr.strip()
    while _wraps_whole(expr):
        expr = expr[1:-1].strip()
    return expr


def _combine_and(statuses: list[Status]) -> Status:
    if all(s is Status.FREE for s in statuses):
        return Status.FREE
    if Status.NONFREE in statuses:
        return Status.SEMIFREE if Status.FREE in statuses else Status.NONFREE
    return Status.UNKNOWN


_OR_RANK = {Status.FREE: 0, Status.SEMIFREE: 1, Status.UNKNOWN: 2, Status.USES_NONFREE: 3, Status.NONFREE: 4}


def classify(license_expr: str | None) -> Status:
    """Classify a license string.

    ``A OR B`` is as free as its freest branch (you may pick it); ``A AND B`` mixing
    free and non-free parts is semifree. Free-text strings ("Apache License 2.0",
    "Freeware") are matched by keyword; anything unrecognised is UNKNOWN.
    """
    if not license_expr or not license_expr.strip():
        return Status.UNKNOWN
    # The PyPI classifier "Other/Proprietary License" is one term, not "Other OR Proprietary".
    expr = _strip_parens(_OTHER_PROPRIETARY.sub("Proprietary", license_expr))
    branches = _split_top_level(expr, _OR)
    if len(branches) > 1:
        return min((classify(b) for b in branches), key=_OR_RANK.__getitem__)
    terms = _split_top_level(expr, _AND)
    if len(terms) > 1:
        return _combine_and([classify(t) for t in terms])
    return _classify_leaf(expr)


def classify_many(licenses: list[str]) -> Status:
    """Several declared licenses (npm/gem/hex style lists) mean the user may pick any."""
    return classify(" OR ".join(f"({lic})" for lic in licenses if lic)) if licenses else Status.UNKNOWN


def sniff_text(text: str) -> str | None:
    """Guess an SPDX id from the opening of a license text."""
    head = text[:4000]
    for phrase, spdx in _data()["fingerprints"]:
        if phrase.lower() in head.lower():
            return str(spdx)
    return None


def sniff_dir(directory: Path) -> str | None:
    """Look for a LICENSE/COPYING file in ``directory`` and sniff it."""
    for name in LICENSE_FILE_NAMES:
        path = directory / name
        if path.is_file():
            try:
                return sniff_text(path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                return None
    return None
