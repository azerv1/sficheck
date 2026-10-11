"""Classify license strings (SPDX expressions or free text) and sniff LICENSE files."""

from __future__ import annotations

import json
import re
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any

from license_expression import ExpressionError, Licensing

from absolutely_proprietary.models import Status

LICENSE_FILE_NAMES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "LICENCE.md", "COPYING", "COPYING.md")

_SUFFIXES = re.compile(r"(-only|-or-later|\+)$", re.IGNORECASE)
# Free-text separators ("MIT/Apache-2.0", R's "GPL-2 | GPL-3", "A && B") rewritten as SPDX operators.
_SEPARATORS = ((re.compile(r"\s*(\|\|?|/)\s*"), " OR "), (re.compile(r"\s*&&?\s*"), " AND "))
_LICENSING = Licensing()
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
    from spdx_license_list import LICENSES

    ids = [i for i, lic in LICENSES.items() if lic.fsf_libre or lic.osi_approved] + _data()["extra_free_spdx"]
    return frozenset(_SUFFIXES.sub("", i).lower() for i in ids)


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
    expr = _OTHER_PROPRIETARY.sub("Proprietary", license_expr)
    spdx = expr
    for separator, operator in _SEPARATORS:
        spdx = separator.sub(operator, spdx)
    try:
        return _status(_LICENSING.parse(spdx))
    except ExpressionError:  # free text the grammar can't hold, e.g. "GPL (>= 2)"
        return _classify_leaf(expr)


def _status(node: Any) -> Status:
    if isinstance(node, _LICENSING.OR):
        return min((_status(arg) for arg in node.args), key=_OR_RANK.__getitem__)
    if isinstance(node, _LICENSING.AND):
        return _combine_and([_status(arg) for arg in node.args])
    return _classify_leaf(str(node))


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
