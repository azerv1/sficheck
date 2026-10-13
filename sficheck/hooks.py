"""Package-manager hooks that warn before something nonfree is installed (Linux, needs root)."""

from __future__ import annotations

import os
import shlex
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

from sficheck import proc
from sficheck.classify import Classifier
from sficheck.models import Package
from sficheck.sources.base import Source

HOOK_FILES = {
    "pacman": Path("/etc/pacman.d/hooks/sficheck.hook"),
    "apt": Path("/etc/apt/apt.conf.d/50sficheck"),
    "dnf": Path("/etc/dnf/libdnf5-plugins/actions.d/sficheck.actions"),
}
# The source whose rules decide each package manager's targets.
HOOK_SOURCES = {"pacman": "pacman", "apt": "dpkg", "dnf": "rpm"}
# Installed by libdnf5-plugin-actions; without it dnf ignores actions.d.
DNF_ACTIONS_CONF = Path("/etc/dnf/libdnf5-plugins/actions.conf")


def sficheck_command() -> list[str]:
    """How a hook should start this sficheck: hooks need absolute paths, since root's PATH differs."""
    script = Path(sys.argv[0]).resolve()
    if script.name == "__main__.py":  # python -m sficheck
        return [sys.executable, "-m", "sficheck"]
    return [str(script)]


def hook_text(manager: str, command: list[str]) -> str:
    check = shlex.join([*command, "--check-targets", HOOK_SOURCES[manager]])
    if manager == "pacman":
        return (
            "# Written by sficheck --install-hook pacman; remove with --remove-hook pacman.\n"
            "[Trigger]\nOperation = Install\nType = Package\nTarget = *\n\n"
            "[Action]\nDescription = Checking new packages for nonfree software (sficheck)...\n"
            f"When = PreTransaction\nExec = {check}\nNeedsTargets\n"
        )
    if manager == "apt":
        # Version 2 of the protocol sends old versions too, so upgrades can be told apart from new installs.
        return (
            "// Written by sficheck --install-hook apt; remove with --remove-hook apt.\n"
            f"DPkg::Pre-Install-Pkgs {{ {_apt_quote(check)}; }};\n"
            f'DPkg::Tools::Options::{command[0]}::Version "2";\n'
        )
    # dnf5 runs the command once per package; the sh guard skips upgrades and removals cheaply.
    script = f"[ '${{pkg.action}}' = I ] || exit 0; exec {check} '${{pkg.name}}' '${{pkg.license}}'"
    escaped = script.replace(" ", "\\ ")  # unescaped spaces would split the command into arguments
    return f"# Written by sficheck --install-hook dnf; remove with --remove-hook dnf.\npre_transaction:*:in::/bin/sh -c {escaped}\n"


def _apt_quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _is_linux() -> bool:
    return sys.platform.startswith("linux")


def _is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def install(manager: str) -> str:
    """Write the hook file; returns what was done, or raises OSError with the reason."""
    if not _is_linux():
        raise OSError("package-manager hooks are only supported on Linux")
    if not _is_root():
        raise OSError(f"writing {HOOK_FILES[manager]} needs root; run it with sudo")
    path = HOOK_FILES[manager]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(hook_text(manager, sficheck_command()), encoding="utf-8")
    note = ""
    if manager == "dnf" and not DNF_ACTIONS_CONF.is_file():
        note = " dnf only runs it once libdnf5-plugin-actions is installed."
    return f"Installed {path}.{note}"


def remove(manager: str) -> str:
    path = HOOK_FILES[manager]
    if not path.exists():
        return f"No sficheck hook at {path}."
    if not _is_root():
        raise OSError(f"removing {path} needs root; run it with sudo")
    path.unlink()
    return f"Removed {path}."


def _apt_targets(lines: Iterable[str]) -> Iterator[tuple[str, str, str]]:
    """(name, new version, .deb path) of the packages apt is about to install fresh (protocol version 2)."""
    it = iter(lines)
    if next(it, "").strip() != "VERSION 2":
        return
    for line in it:  # the configuration dump ends at the first blank line
        if not line.strip():
            break
    for line in it:
        fields = line.split()
        if len(fields) == 5 and fields[1] == "-" and fields[4].endswith(".deb"):
            yield fields[0], fields[3], fields[4]


def targets(source: Source, stdin: Iterable[str], args: list[str]) -> list[Package]:
    """The packages a hook asks about: names on stdin (pacman), apt's protocol, or dnf's name and license."""
    if source.name == "pacman":
        return [source.pkg(name) for name in (line.strip() for line in stdin) if name]
    if source.name == "dpkg":
        found = []
        for name, version, deb in _apt_targets(stdin):
            section = (proc.run(["dpkg-deb", "-f", deb, "Section"]) or "").strip()
            found.append(source.pkg(name, version, section=section))
        return found
    name, license_ = ([*args, "", ""])[:2]
    return [source.pkg(name, "", license_)] if name else []


def check(source: Source, packages: list[Package], classifier: Classifier) -> list[str]:
    """One warning line per proprietary package."""
    source.prepare()
    warnings = []
    for f in classifier.run(source, packages):
        if f.status.is_proprietary:
            why = f.description or f.reason
            alternatives = f"; free alternatives: {', '.join(f.alternatives)}" if f.alternatives else ""
            warnings.append(f"sficheck: {f.package.name} is {f.status.value} ({why}){alternatives}")
    return warnings
