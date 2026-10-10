"""Output formats: terminal table, markdown, JSON, CSV."""

from __future__ import annotations

import csv
import io
import json
import textwrap
from collections.abc import Sequence
from dataclasses import dataclass

from absolutely_proprietary.models import Finding, SourceReport, Status

HEADERS = ("Source", "Name", "Version", "Status", "Libre alternatives", "Description")


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

    def index(self, text: str, value: float | None) -> str:
        if value is None:
            return text
        return self.wrap(text, "32" if value > 95 else "33" if value > 25 else "31")


def _row(f: Finding) -> tuple[str, str, str, str, list[str], str]:
    desc = f.description or f.reason
    if f.description and f.reason not in ("", "license"):
        desc += f" [{f.reason}]"
    return f.package.source, f.package.name, f.package.version, f.status.value, list(f.alternatives), desc


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


def summary_text(reports: Sequence[SourceReport], palette: Palette, unknown_as_nonfree: bool) -> str:
    overall = _overall(reports)
    idx = overall.freedom_index(unknown_as_nonfree)
    bar = "=" * 45
    lines = [
        palette.index(f"{bar}\n{overall.proprietary} ABSOLUTELY PROPRIETARY PACKAGES INSTALLED\n{bar}", idx),
        "",
        f"Your system is infected with {palette.index(str(overall.proprietary), idx)} proprietary packages "
        f"out of {overall.total} found ({overall.unknown} unknown) across {len(reports)} sources.",
        f"Your Stallman Freedom Index is {palette.index(_fmt_index(idx), idx)}",
        "",
    ]
    rows = [[["Source"], ["Packages"], ["Proprietary"], ["Unknown"], ["Freedom index"]]]
    for r in reports:
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
    for src, name, ver, status, alts, desc in raw:
        for i, value in enumerate((src, name, ver, status, max(alts, key=len, default=""), desc)):
            natural[i] = max(natural[i], len(value))
    widths = _fit_widths(natural, max_width, shrinkable=(5, 4, 1, 2))
    rows: list[list[list[str]]] = [[[h] for h in HEADERS]]
    for src, name, ver, status, alts, desc in raw:
        cells = [
            textwrap.wrap(src, widths[0]) or [""],
            textwrap.wrap(name, widths[1], break_on_hyphens=False) or [""],
            textwrap.wrap(ver, widths[2]) or [""],
            [status],
            [line for alt in alts for line in textwrap.wrap(alt, widths[4])] or [""],
            textwrap.wrap(desc, widths[5]) or [""],
        ]
        rows.append(cells)
    text = _grid(rows, widths)
    if palette.enabled:
        # Colour the status cells after layout so escape codes don't break alignment.
        for status in Status:
            text = text.replace(
                f"| {status.value.ljust(widths[3])} |", f"| {palette.status(status.value.ljust(widths[3]), status)} |"
            )
    return text + "\n"


def markdown(findings: Sequence[Finding], reports: Sequence[SourceReport], unknown_as_nonfree: bool) -> str:
    def esc(text: str) -> str:
        return text.replace("|", "\\|")

    lines = ["| Source | Packages | Proprietary | Unknown | Freedom index |", "|---|---:|---:|---:|---:|"]
    for r in [*reports, _overall(reports)]:
        lines.append(
            f"| {r.source} | {r.total} | {r.proprietary} | {r.unknown} | {_fmt_index(r.freedom_index(unknown_as_nonfree))} |"
        )
    headers = (*HEADERS, "Reference")
    lines += ["", "| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for f in findings:
        src, name, ver, status, alts, desc = _row(f)
        ref = f"[source]({f.reference})" if f.reference else ""
        lines.append("| " + " | ".join(esc(x) for x in (src, name, ver, status, "<br>".join(alts), desc, ref)) + " |")
    return "\n".join(lines) + "\n"


def as_json(findings: Sequence[Finding], reports: Sequence[SourceReport], unknown_as_nonfree: bool) -> str:
    overall = _overall(reports)
    doc = {
        "summary": {
            "total": overall.total,
            "proprietary": overall.proprietary,
            "unknown": overall.unknown,
            "freedom_index": overall.freedom_index(unknown_as_nonfree),
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
        src, name, ver, status, alts, _ = _row(f)
        row = [src, name, ver, status, "; ".join(alts), f.description, f.package.license or "", f.reason, f.reference]
        writer.writerow(row)
    return buf.getvalue()
