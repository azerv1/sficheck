"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from absolutely_proprietary import __version__, render
from absolutely_proprietary.blacklist import Blacklist, load_user
from absolutely_proprietary.classify import Classifier
from absolutely_proprietary.models import Finding, SourceReport, Status
from absolutely_proprietary.net import Fetcher
from absolutely_proprietary.sources import ALL_SOURCES, BY_NAME, Context, Source

log = logging.getLogger("absolutely_proprietary")

PROPRIETARY = [Status.NONFREE.value, Status.SEMIFREE.value, Status.USES_NONFREE.value]
SORT_KEYS = {
    "source": lambda f: (f.package.source, f.package.name.lower()),
    "name": lambda f: f.package.name.lower(),
    "status": lambda f: (f.status.value, f.package.name.lower()),
    "alternatives": lambda f: (", ".join(f.alternatives).lower(), f.package.name.lower()),
}


def config_path() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "absolutely-proprietary" / "config.json"


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="absolutely-proprietary",
        description="Find proprietary software installed through your system and language package managers.",
        epilog=f"Defaults for any option can be set in {config_path()} (JSON, keys = option names with underscores).",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    g = p.add_argument_group("what to scan")
    g.add_argument("--sources", type=_csv, metavar="A,B", help="only scan these sources (see --list-sources)")
    g.add_argument("--skip", type=_csv, default=[], metavar="A,B", help="skip these sources")
    g.add_argument(
        "--kind",
        choices=["system", "lang"],
        action="append",
        help="only scan sources of this kind (repeatable)",
    )
    g.add_argument(
        "--list-sources", action="store_true", help="show every source and whether it's available here, then exit"
    )

    g = p.add_argument_group("what to show")
    g.add_argument(
        "--status",
        action="append",
        choices=[s.value for s in Status] + ["all"],
        help="show packages with this status (repeatable; default: nonfree)",
    )
    g.add_argument("--all", dest="status", action="append_const", const="all", help="show every package, free ones too")
    g.add_argument("-f", "--full", action="store_true", help="show nonfree, semifree and uses-nonfree packages")
    g.add_argument("--show-unknown", action="store_true", help="also show packages that couldn't be classified")
    g.add_argument(
        "--unknown-as-nonfree", action="store_true", help="count unknown packages as proprietary in the index"
    )
    g.add_argument("--sort", choices=list(SORT_KEYS), default="source", help="sort column (default: source)")
    g.add_argument(
        "-s", "--sort-status", dest="sort", action="store_const", const="status", help="same as --sort status"
    )
    g.add_argument(
        "-a",
        "--sort-alternative",
        dest="sort",
        action="store_const",
        const="alternatives",
        help="same as --sort alternatives",
    )
    g.add_argument("-r", "--reverse", action="store_true", help="reverse the sort")

    g = p.add_argument_group("output")
    g.add_argument("--format", choices=["table", "markdown", "json", "csv"], default="table")
    g.add_argument("-o", "--output", type=Path, metavar="FILE", help="write the report to FILE instead of stdout")
    g.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    g.add_argument("-q", "--quiet", action="store_true", help="no progress messages")
    g.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    g.add_argument("--exit-code", action="store_true", help="exit with status 1 if any proprietary package is found")

    g = p.add_argument_group("blacklists and lookups")
    g.add_argument(
        "--blacklist",
        action="append",
        default=[],
        metavar="PATH|URL",
        help="extra blacklist (Parabola text format or bundled JSON format); overrides everything else",
    )
    g.add_argument(
        "--ignore", action="append", default=[], metavar="PKG", help="never report this package (repeatable)"
    )
    g.add_argument("--no-bundled", action="store_true", help="don't use the bundled curated lists")
    g.add_argument(
        "--include-privacy", action="store_true", help="also apply Parabola's your-privacy blacklist (pacman)"
    )
    g.add_argument(
        "--online-licenses",
        action="store_true",
        help="look up missing licenses online (deps.dev, packagist, pub.dev, hex.pm, metacpan, GitHub)",
    )
    g.add_argument("--offline", action="store_true", help="never use the network; rely on cached downloads")
    g.add_argument("--refresh", action="store_true", help="ignore cached downloads younger than --cache-ttl")
    g.add_argument(
        "--cache-ttl", type=float, default=24, metavar="HOURS", help="how long downloads are cached (default: 24)"
    )
    g.add_argument("--jobs", type=int, default=8, help="parallel workers (default: 8)")
    g.add_argument("--config", type=Path, default=None, help=argparse.SUPPRESS)
    return p


def load_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.warning("Ignoring config %s: %s", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = build_parser()
    pre, _ = parser.parse_known_args(argv)
    config = load_config(pre.config or config_path())
    unknown = set(config) - {a.dest for a in parser._actions}
    if unknown:
        log.warning("Unknown config keys ignored: %s", ", ".join(sorted(unknown)))
    parser.set_defaults(**{k: v for k, v in config.items() if k not in unknown})
    args = parser.parse_args(argv)
    if args.sources:
        bad = [s for s in args.sources if s not in BY_NAME]
        if bad:
            parser.error(f"unknown source(s): {', '.join(bad)} (choose from {', '.join(BY_NAME)})")
    return args


def wanted_statuses(args: argparse.Namespace) -> set[str]:
    if args.status:
        return {s.value for s in Status} if "all" in args.status else set(args.status)
    statuses = set(PROPRIETARY) if args.full else {Status.NONFREE.value}
    if args.show_unknown:
        statuses.add(Status.UNKNOWN.value)
    return statuses


def select_sources(args: argparse.Namespace, ctx: Context) -> list[Source]:
    classes = [BY_NAME[n] for n in args.sources] if args.sources else [c for c in ALL_SOURCES if c.default_enabled]
    classes = [c for c in classes if c.name not in args.skip and (not args.kind or c.kind in args.kind)]
    return [src for src in (c(ctx) for c in classes) if src.available()]


def list_sources(ctx: Context) -> str:
    lines = []
    for cls in ALL_SOURCES:
        src = cls(ctx)
        state = "available" if src.available() else "-"
        opt = "" if cls.default_enabled else " (opt-in)"
        lines.append(f"{cls.name:<10} {cls.kind:<9} {state:<10} {cls.description}{opt}")
    return "\n".join(lines) + "\n"


def scan(sources: list[Source], classifier: Classifier, jobs: int) -> list[SourceReport]:
    def one(src: Source) -> SourceReport:
        report = SourceReport(src.name, src.kind)
        log.info("Scanning %s...", src.name)
        try:
            report.findings = classifier.run(src, list(src.packages()))
        except Exception as exc:  # one broken package manager shouldn't sink the whole report
            log.warning("%s: %s", src.name, exc)
            log.debug("traceback", exc_info=True)
            report.error = str(exc) or type(exc).__name__
        return report

    with ThreadPoolExecutor(max(1, min(jobs, len(sources) or 1))) as pool:
        return list(pool.map(one, sources))


def _use_color(choice: str, stream: Any) -> bool:
    if choice != "auto":
        return choice == "always"
    if os.environ.get("NO_COLOR") or not getattr(stream, "isatty", lambda: False)():
        return False
    return _enable_windows_vt()


def _enable_windows_vt() -> bool:
    """Turn on ANSI escape processing in the Windows console."""
    if sys.platform != "win32":
        return True
    import ctypes

    kernel32 = ctypes.windll.kernel32
    handle = kernel32.GetStdHandle(-11)
    mode = ctypes.c_uint32()
    if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
        return False
    return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))


def render_report(args: argparse.Namespace, reports: list[SourceReport], shown: list[Finding], color: bool) -> str:
    if args.format == "json":
        return render.as_json(shown, reports, args.unknown_as_nonfree)
    if args.format == "csv":
        return render.as_csv(shown)
    if args.format == "markdown":
        return render.markdown(shown, reports, args.unknown_as_nonfree)
    palette = render.Palette(color)
    width = 10_000 if args.output else shutil.get_terminal_size((160, 24)).columns
    return render.summary_text(reports, palette, args.unknown_as_nonfree) + "\n" + render.table(shown, palette, width)


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            # Piped output on Windows would otherwise use the ANSI code page and mangle names.
            stream.reconfigure(errors="replace", **({} if stream.isatty() else {"encoding": "utf-8"}))
    logging.basicConfig(format="%(message)s", stream=sys.stderr)
    args = parse_args(argv)
    log.setLevel(logging.DEBUG if args.verbose else logging.WARNING if args.quiet else logging.INFO)

    fetcher = Fetcher(ttl=args.cache_ttl * 3600, offline=args.offline, refresh=args.refresh)
    ctx = Context(fetcher=fetcher, include_privacy=args.include_privacy, jobs=args.jobs)
    if args.list_sources:
        sys.stdout.write(list_sources(ctx))
        return 0

    user = Blacklist()
    for location in args.blacklist:
        try:
            user = user.merged(load_user(location, fetcher))
        except (OSError, ValueError, KeyError) as exc:
            log.error("Could not load blacklist %s: %s", location, exc)
            return 2

    sources = select_sources(args, ctx)
    if not sources:
        log.error("No supported package sources found (try --list-sources).")
        return 2
    classifier = Classifier(
        fetcher=fetcher,
        user=user,
        ignore=frozenset(n.lower() for n in args.ignore),
        use_bundled=not args.no_bundled,
        online=args.online_licenses and not args.offline,
        jobs=args.jobs,
    )
    reports = scan(sources, classifier, args.jobs)

    statuses = wanted_statuses(args)
    shown = [f for r in reports for f in r.findings if f.status.value in statuses]
    shown.sort(key=SORT_KEYS[args.sort], reverse=args.reverse)

    if args.output:
        text = render_report(args, reports, shown, color=False)
        args.output.expanduser().parent.mkdir(parents=True, exist_ok=True)
        args.output.expanduser().write_text(text, encoding="utf-8")
        log.info("Report saved to %s", args.output.expanduser().resolve())
    else:
        sys.stdout.write(render_report(args, reports, shown, color=_use_color(args.color, sys.stdout)))

    found_proprietary = any(f.status.is_proprietary for r in reports for f in r.findings)
    return 1 if args.exit_code and found_proprietary else 0
