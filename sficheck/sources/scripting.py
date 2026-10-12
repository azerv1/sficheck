"""Scripting & functional languages: Ruby, PHP, Perl, Lua, R, Julia, Dart, Haskell, Elixir."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path

from sficheck import licenses, proc
from sficheck.models import Package
from sficheck.sources import meta
from sficheck.sources.base import IS_WINDOWS, Source, env_path


def _join(lics: object) -> str | None:
    """A list of declared licenses means the user may pick any of them."""
    if isinstance(lics, str):
        return lics or None
    if isinstance(lics, list):
        names = [str(x) for x in lics if x]
        return " OR ".join(f"({n})" for n in names) or None
    return None


_GEM_SCRIPT = (
    'require "json"; puts Gem::Specification.map { |s| '
    '{ "name" => s.name, "version" => s.version.to_s, "licenses" => s.licenses } }.to_json'
)


class Gem(Source):
    name = "gem"
    description = "Installed Ruby gems (gemspec licenses)"
    registry = "rubygems"

    def available(self) -> bool:
        return proc.which("ruby") is not None

    def packages(self) -> Iterable[Package]:
        out = proc.run(["ruby", "-e", _GEM_SCRIPT])
        for spec in json.loads(out) if out else []:
            yield self.pkg(spec["name"], spec["version"], _join(spec.get("licenses")))


class Composer(Source):
    name = "composer"
    description = "Global Composer packages (composer.json license)"
    registry = "packagist"

    def available(self) -> bool:
        return proc.which("composer") is not None

    def packages(self) -> Iterable[Package]:
        home = (proc.run(["composer", "global", "config", "home", "--no-interaction"]) or "").strip()
        installed = meta.read_json(Path(home) / "vendor" / "composer" / "installed.json") if home else None
        # Composer 2 wraps the list in {"packages": [...]}; Composer 1 is a bare list.
        items = installed.get("packages", []) if isinstance(installed, dict) else installed or []
        for item in items:
            yield self.pkg(item["name"], str(item.get("version", "")), _join(item.get("license")))


_PERL_INC = "print join(qq{\\n}, grep { -d } @INC)"


class Cpan(Source):
    name = "cpan"
    description = "Perl distributions installed by cpan/cpanm (MYMETA license)"
    registry = "metacpan"

    def available(self) -> bool:
        return proc.which("perl") is not None

    def packages(self) -> Iterable[Package]:
        seen: set[str] = set()
        for inc in (proc.run(["perl", "-e", _PERL_INC]) or "").splitlines():
            for mymeta in Path(inc).glob(".meta/*/MYMETA.json"):
                data = meta.read_json(mymeta)
                if isinstance(data, dict) and (name := data.get("name")) and name not in seen:
                    seen.add(name)
                    yield self.pkg(name, str(data.get("version", "")), _join(data.get("license")))


class LuaRocks(Source):
    name = "luarocks"
    description = "Installed Lua rocks (rockspec license)"

    def available(self) -> bool:
        return proc.which("luarocks") is not None

    def packages(self) -> Iterable[Package]:
        for line in (proc.run(["luarocks", "list", "--porcelain"]) or "").splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            show = proc.run(["luarocks", "show", parts[0], parts[1]]) or ""
            match = re.search(r"^License:\s*(.+)$", show, re.MULTILINE)
            yield self.pkg(parts[0], parts[1], match.group(1).strip() if match else None)


_R_SCRIPT = (
    'ip <- installed.packages(fields = "License"); '
    'write.table(ip[, c("Package", "Version", "License")], sep = "\\t", quote = FALSE, row.names = FALSE, col.names = FALSE)'
)


class CranR(Source):
    name = "r"
    description = "Installed R packages (DESCRIPTION License)"

    def available(self) -> bool:
        return proc.which("Rscript") is not None

    def packages(self) -> Iterable[Package]:
        seen: set[str] = set()
        for line in (proc.run(["Rscript", "-e", _R_SCRIPT]) or "").splitlines():
            parts = line.split("\t")
            if len(parts) == 3 and parts[0] not in seen:
                seen.add(parts[0])
                # R writes "GPL-2 | GPL-3" and appends "+ file LICENSE"; the latter adds no information.
                yield self.pkg(parts[0], parts[1], parts[2].replace("+ file LICENSE", "").strip())


_JULIA_SCRIPT = (
    "using Pkg; for (_, d) in Pkg.dependencies(); d.is_direct_dep && "
    'println(d.name, "\\t", something(d.version, ""), "\\t", something(d.source, "")); end'
)


class Julia(Source):
    name = "julia"
    description = "Packages in the default Julia environment (LICENSE file)"

    def available(self) -> bool:
        return proc.which("julia") is not None

    def packages(self) -> Iterable[Package]:
        for line in (proc.run(["julia", "--startup-file=no", "-e", _JULIA_SCRIPT], timeout=300) or "").splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                yield self.pkg(parts[0], parts[1], licenses.sniff_dir(Path(parts[2])) if parts[2] else None)


def _pub_cache() -> Path:
    default = Path.home() / "AppData" / "Local" / "Pub" / "Cache" if IS_WINDOWS else Path.home() / ".pub-cache"
    return env_path("PUB_CACHE", default)


class Pub(Source):
    name = "pub"
    description = "Dart/Flutter global packages (LICENSE file, pub.dev)"
    registry = "pub"

    def available(self) -> bool:
        return proc.which("dart") is not None

    def packages(self) -> Iterable[Package]:
        for line in (proc.run(["dart", "pub", "global", "list"]) or "").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                name, version = parts[0], parts[1]
                yield self.pkg(
                    name, version, licenses.sniff_dir(_pub_cache() / "hosted" / "pub.dev" / f"{name}-{version}")
                )


class GhcPkg(Source):
    name = "ghc-pkg"
    description = "Haskell packages registered with GHC (cabal license field)"

    def available(self) -> bool:
        return proc.which("ghc-pkg") is not None

    def packages(self) -> Iterable[Package]:
        out = proc.run(["ghc-pkg", "field", "*", "name,version,license"]) or ""
        seen: set[str] = set()
        for block in re.split(r"\n(?=name:)", out):
            fields = dict(re.findall(r"^(\w+):\s*(.*)$", block, re.MULTILINE))
            if (name := fields.get("name")) and name not in seen:
                seen.add(name)
                yield self.pkg(name, fields.get("version", ""), fields.get("license"))


class Mix(Source):
    name = "mix"
    description = "Elixir archives and escripts (hex.pm license)"
    registry = "hex"

    def available(self) -> bool:
        return proc.which("mix") is not None

    def packages(self) -> Iterable[Package]:
        for line in (proc.run(["mix", "archive"]) or "").splitlines():
            if match := re.match(r"^\*\s+(\S+?)-(\d[\w.+-]*)$", line.strip()):
                yield self.pkg(match.group(1), match.group(2))
        escripts = Path.home() / ".mix" / "escripts"
        if escripts.is_dir():
            for script in escripts.iterdir():
                yield self.pkg(script.stem)
