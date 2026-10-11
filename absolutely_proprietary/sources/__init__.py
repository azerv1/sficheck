"""All package sources, in report order."""

from __future__ import annotations

from absolutely_proprietary.sources.base import Context, Source
from absolutely_proprietary.sources.compiled import Cargo, Conan, DotnetTools, Go, Mint, NugetCache, Vcpkg
from absolutely_proprietary.sources.firmware import Firmware
from absolutely_proprietary.sources.hypervisors import Hypervisors
from absolutely_proprietary.sources.javascript import Bun, Deno, Npm, Pnpm, Yarn
from absolutely_proprietary.sources.jvm import Coursier, Gradle, Maven, Sdkman
from absolutely_proprietary.sources.kernel import Kernel
from absolutely_proprietary.sources.python import Pip, Pipx, UvTools
from absolutely_proprietary.sources.scripting import Composer, Cpan, CranR, Gem, GhcPkg, Julia, LuaRocks, Mix, Pub
from absolutely_proprietary.sources.system import Brew, Dpkg, Flatpak, Nix, Pacman, Snap
from absolutely_proprietary.sources.windows import Chocolatey, Scoop, WindowsRegistry, Winget

ALL_SOURCES: tuple[type[Source], ...] = (
    # system
    Pacman,
    Dpkg,
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
