"""JavaScript/TypeScript: global installs from npm, pnpm, yarn, bun and deno."""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from sficheck import proc
from sficheck.models import Package
from sficheck.sources import meta
from sficheck.sources.base import Source, env_path


class Npm(Source):
    name = "npm"
    description = "Global npm packages (package.json license)"
    registry = "npm"
    tool = "npm"
    root_cmd: tuple[str, ...] = ("npm", "root", "-g")

    def available(self) -> bool:
        return proc.which(self.tool) is not None

    def global_root(self) -> Path | None:
        out = (proc.run(list(self.root_cmd)) or "").strip()
        return Path(out) if out else None

    def packages(self) -> Iterable[Package]:
        root = self.global_root()
        for name, version, lic, _ in meta.node_modules(root) if root else ():
            yield self.pkg(name, version, lic)


class Pnpm(Npm):
    name = "pnpm"
    description = "Global pnpm packages"
    tool = "pnpm"
    root_cmd = ("pnpm", "root", "-g")


class Yarn(Npm):
    name = "yarn"
    description = "Global yarn (classic) packages"
    tool = "yarn"
    root_cmd = ("yarn", "global", "dir")

    def global_root(self) -> Path | None:
        root = super().global_root()
        return root / "node_modules" if root else None


class Bun(Npm):
    name = "bun"
    description = "Global bun packages"
    tool = "bun"

    def global_root(self) -> Path | None:
        return env_path("BUN_INSTALL", Path.home() / ".bun") / "install" / "global" / "node_modules"


_DENO_SPEC = re.compile(r"\b(npm|jsr):(@?[\w.-]+(?:/[\w.-]+)?)(?:@([\w.^~<>=-]+))?")


class Deno(Source):
    name = "deno"
    description = "Scripts installed with `deno install -g` (npm: specs looked up online)"
    registry = "npm"

    def available(self) -> bool:
        return proc.which("deno") is not None

    def packages(self) -> Iterable[Package]:
        bin_dir = env_path("DENO_INSTALL_ROOT", Path.home() / ".deno") / "bin"
        if not bin_dir.is_dir():
            return
        for shim in bin_dir.iterdir():
            if shim.stem in ("deno", "denort") or not shim.is_file() or shim.stat().st_size > 64_000:
                continue
            match = _DENO_SPEC.search(shim.read_text(encoding="utf-8", errors="replace"))
            if match and match.group(1) == "npm":
                yield self.pkg(match.group(2), match.group(3) or "")
            elif match:
                yield self.pkg(f"jsr:{match.group(2)}", match.group(3) or "")
            else:
                yield self.pkg(shim.stem)
