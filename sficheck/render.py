"""Output formats: terminal table, markdown, JSON, CSV."""

from __future__ import annotations

import csv
import io
import json
import textwrap
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from sficheck.models import Finding, Ring, SourceReport, Status

HEADERS = ("Source", "Name", "Version", "Status", "Ring", "Libre alternatives", "Description")


def ring_label(ring: Ring | None) -> str:
    if ring is None:
        return ""
    return f"{ring.value} {ring.name if ring is Ring.ME else ring.name.lower()}"  # ME is an acronym


@dataclass(frozen=True, slots=True)
class Palette:
    enabled: bool

    def wrap(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled and text else text

    def status(self, text: str, status: Status) -> str:
        code = {
            Status.NONFREE: "31",
            Status.SEMIFREE: "33",
            Status.USES_NONFREE: "33",
            Status.FREE: "32",
            Status.UNKNOWN: "2",
        }
        return self.wrap(text, code[status])

    def ring(self, text: str, ring: Ring | None) -> str:
        if ring is None or ring is Ring.USER:
            return text
        return self.wrap(text, "31" if ring is Ring.KERNEL else "1;31")  # below the kernel: bold

    def index(self, text: str, value: float | None) -> str:
        if value is None:
            return text
        return self.wrap(text, "32" if value > 95 else "33" if value > 25 else "31")


def _row(f: Finding) -> tuple[str, str, str, str, str, list[str], str]:
    desc = f.description or f.reason
    if f.description and f.reason not in ("", "license"):
        desc += f" [{f.reason}]"
    return (
        f.package.source,
        f.package.name,
        f.package.version,
        f.status.value,
        ring_label(f.ring),
        list(f.alternatives),
        desc,
    )


def _ring_counts(findings: Sequence[Finding]) -> dict[Ring, int]:
    """How many findings sit in each ring, deepest first; rings with none are left out."""
    counts = Counter(f.ring for f in findings if f.ring is not None)
    return {ring: counts[ring] for ring in sorted(counts)}


def _fmt_index(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def _overall(reports: Sequence[SourceReport]) -> SourceReport:
    combined = SourceReport("all", "")
    for report in reports:
        combined.findings.extend(report.findings)
    return combined


def _grid(rows: list[list[list[str]]], widths: list[int]) -> str:
    """Draw +---+ boxes around rows whose cells are lists of already-wrapped lines."""
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    out = [sep]
    for row in rows:
        for line_no in range(max(len(cell) for cell in row)):
            cells = [(cell[line_no] if line_no < len(cell) else "") for cell in row]
            out.append("| " + " | ".join(c.ljust(w) for c, w in zip(cells, widths, strict=True)) + " |")
        out.append(sep)
    return "\n".join(out)


def _fit_widths(natural: list[int], max_total: int, shrinkable: Sequence[int]) -> list[int]:
    """Shrink the ``shrinkable`` columns (widest first) until the table fits ``max_total``."""
    widths = list(natural)
    overhead = 3 * len(widths) + 1
    while sum(widths) + overhead > max_total:
        col = max(shrinkable, key=lambda c: widths[c])
        if widths[col] <= 12:
            break
        widths[col] -= 1
    return widths


def _with_packages(reports: Sequence[SourceReport]) -> list[SourceReport]:
    """The sources worth a row: ones that found something, or failed."""
    return [r for r in reports if r.total or r.error]


def summary_text(reports: Sequence[SourceReport], palette: Palette, unknown_as_nonfree: bool) -> str:
    overall = _overall(reports)
    idx = overall.freedom_index(unknown_as_nonfree)
    bar = "=" * 45
    lines = [
        palette.index(f"{bar}\n{overall.proprietary} ABSOLUTELY PROPRIETARY PACKAGES INSTALLED\n{bar}", idx),
        "",
        f"Your system is infected with {palette.index(str(overall.proprietary), idx)} proprietary packages "
        f"out of {overall.total} found ({overall.unknown} unknown) across {len(_with_packages(reports))} sources.",
        f"Your Stallman Freedom Index is {palette.index(_fmt_index(idx), idx)}",
    ]
    if rings := _ring_counts(overall.findings):
        by_ring = ", ".join(f"{palette.ring(ring_label(r), r)}: {n}" for r, n in rings.items())
        lines.append(f"By protection ring: {by_ring}")
    lines.append("")
    rows = [[["Source"], ["Packages"], ["Proprietary"], ["Unknown"], ["Freedom index"]]]
    for r in _with_packages(reports):
        ri = r.freedom_index(unknown_as_nonfree)
        rows.append(
            [
                [r.source],
                [str(r.total)],
                [str(r.proprietary)],
                [str(r.unknown)],
                [_fmt_index(ri)] if not r.error else [f"error: {r.error}"],
            ]
        )
    widths = [max(len(cell[0]) for cell in col) for col in zip(*rows, strict=True)]
    lines.append(_grid(rows, widths))
    return "\n".join(lines) + "\n"


def table(findings: Sequence[Finding], palette: Palette, max_width: int) -> str:
    if not findings:
        return "No matching packages.\n"
    raw = [_row(f) for f in findings]
    natural = [len(h) for h in HEADERS]
    for src, name, ver, status, ring, alts, desc in raw:
        for i, value in enumerate((src, name, ver, status, ring, max(alts, key=len, default=""), desc)):
            natural[i] = max(natural[i], len(value))
    widths = _fit_widths(natural, max_width, shrinkable=(6, 5, 1, 2))
    rows: list[list[list[str]]] = [[[h] for h in HEADERS]]
    for src, name, ver, status, ring, alts, desc in raw:
        cells = [
            textwrap.wrap(src, widths[0]) or [""],
            textwrap.wrap(name, widths[1], break_on_hyphens=False) or [""],
            textwrap.wrap(ver, widths[2]) or [""],
            [status],
            [ring],
            [line for alt in alts for line in textwrap.wrap(alt, widths[5])] or [""],
            textwrap.wrap(desc, widths[6]) or [""],
        ]
        rows.append(cells)
    text = _grid(rows, widths)
    if palette.enabled:
        # Colour the status and ring cells after layout so escape codes don't break alignment.
        # They are matched as a pair so a lone "0" elsewhere in the row is never touched.
        for status in Status:
            for ring in (None, *Ring):
                plain_status, plain_ring = status.value.ljust(widths[3]), ring_label(ring).ljust(widths[4])
                text = text.replace(
                    f"| {plain_status} | {plain_ring} |",
                    f"| {palette.status(plain_status, status)} | {palette.ring(plain_ring, ring)} |",
                )
    return text + "\n"


def markdown(findings: Sequence[Finding], reports: Sequence[SourceReport], unknown_as_nonfree: bool) -> str:
    def esc(text: str) -> str:
        return text.replace("|", "\\|")

    lines = ["| Source | Packages | Proprietary | Unknown | Freedom index |", "|---|---:|---:|---:|---:|"]
    for r in [*_with_packages(reports), _overall(reports)]:
        lines.append(
            f"| {r.source} | {r.total} | {r.proprietary} | {r.unknown} | {_fmt_index(r.freedom_index(unknown_as_nonfree))} |"
        )
    headers = (*HEADERS, "Reference")
    lines += ["", "| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for f in findings:
        src, name, ver, status, ring, alts, desc = _row(f)
        ref = f"[source]({f.reference})" if f.reference else ""
        cells = (src, name, ver, status, ring, "<br>".join(alts), desc, ref)
        lines.append("| " + " | ".join(esc(x) for x in cells) + " |")
    return "\n".join(lines) + "\n"


def as_json(findings: Sequence[Finding], reports: Sequence[SourceReport], unknown_as_nonfree: bool) -> str:
    overall = _overall(reports)
    doc = {
        "summary": {
            "total": overall.total,
            "proprietary": overall.proprietary,
            "unknown": overall.unknown,
            "freedom_index": overall.freedom_index(unknown_as_nonfree),
            "by_ring": {str(r.value): n for r, n in _ring_counts(overall.findings).items()},
            "sources": [
                {
                    "source": r.source,
                    "kind": r.kind,
                    "total": r.total,
                    "proprietary": r.proprietary,
                    "unknown": r.unknown,
                    "freedom_index": r.freedom_index(unknown_as_nonfree),
                    "error": r.error or None,
                }
                for r in reports
            ],
        },
        "findings": [
            {
                "source": f.package.source,
                "name": f.package.name,
                "version": f.package.version,
                "status": f.status.value,
                "ring": None if f.ring is None else f.ring.value,
                "license": f.package.license,
                "alternatives": list(f.alternatives),
                "description": f.description,
                "reason": f.reason,
                "reference": f.reference or None,
            }
            for f in findings
        ],
    }
    return json.dumps(doc, indent=2) + "\n"


def as_csv(findings: Sequence[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow([*HEADERS, "License", "Reason", "Reference"])
    for f in findings:
        src, name, ver, status, _, alts, _ = _row(f)
        ring = "" if f.ring is None else str(f.ring.value)
        row = [
            src,
            name,
            ver,
            status,
            ring,
            "; ".join(alts),
            f.description,
            f.package.license or "",
            f.reason,
            f.reference,
        ]
        writer.writerow(row)
    return buf.getvalue()
