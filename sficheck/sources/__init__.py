"""All package sources, in report order."""

from __future__ import annotations

from sficheck.sources.base import Context, Source
from sficheck.sources.browser import Browser
from sficheck.sources.compiled import Cargo, Conan, DotnetTools, Go, Mint, NugetCache, Vcpkg
from sficheck.sources.firmware import Firmware
from sficheck.sources.hardware import Hardware
from sficheck.sources.hypervisors import Hypervisors
from sficheck.sources.javascript import Bun, Deno, Npm, Pnpm, Yarn
from sficheck.sources.jvm import Coursier, Gradle, Maven, Sdkman
from sficheck.sources.kernel import Kernel
from sficheck.sources.python import Pip, Pipx, UvTools
from sficheck.sources.scripting import Composer, Cpan, CranR, Gem, GhcPkg, Julia, LuaRocks, Mix, Pub
from sficheck.sources.system import Brew, Dpkg, Flatpak, Nix, Pacman, Rpm, Snap
from sficheck.sources.windows import Chocolatey, Scoop, WindowsRegistry, Winget

ALL_SOURCES: tuple[type[Source], ...] = (
    # system
    Pacman,
    Dpkg,
    Rpm,
    Nix,
    Flatpak,
    Snap,
    Brew,
    WindowsRegistry,
    Winget,
    Scoop,
    Chocolatey,
    Kernel,
    Hypervisors,
    Firmware,
    Hardware,
    Browser,
    # languages
    Pip,
    UvTools,
    Pipx,
    Npm,
    Pnpm,
    Yarn,
    Bun,
    Deno,
    Cargo,
    Go,
    Maven,
    Gradle,
    Sdkman,
    Coursier,
    DotnetTools,
    NugetCache,
    Vcpkg,
    Conan,
    Gem,
    Composer,
    Mint,
    Pub,
    CranR,
    Cpan,
    LuaRocks,
    GhcPkg,
    Mix,
    Julia,
)

BY_NAME: dict[str, type[Source]] = {cls.name: cls for cls in ALL_SOURCES}

__all__ = ["ALL_SOURCES", "BY_NAME", "Context", "Source"]
