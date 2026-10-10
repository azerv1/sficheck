"""JVM ecosystems: Maven and Gradle caches, SDKMAN! candidates, Coursier apps."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from absolutely_proprietary import proc
from absolutely_proprietary.models import Finding, Package, Status
from absolutely_proprietary.sources import meta
from absolutely_proprietary.sources.base import Source, env_path


class Maven(Source):
    name = "maven"
    description = "Artifacts in the local Maven repository (can be large; POM licenses)"
    registry = "maven"
    default_enabled = False

    def _root(self) -> Path:
        return Path.home() / ".m2" / "repository"

    def available(self) -> bool:
        return self._root().is_dir()

    def packages(self) -> Iterable[Package]:
        root = self._root()
        # <group path>/<artifact>/<version>/<artifact>-<version>.pom
        for pom in root.rglob("*.pom"):
            version_dir = pom.parent
            artifact = version_dir.parent.name
            if pom.name != f"{artifact}-{version_dir.name}.pom":
                continue
            group = ".".join(version_dir.parent.parent.relative_to(root).parts)
            yield self.pkg(f"{group}:{artifact}", version_dir.name, meta.pom_licenses(pom))


class Gradle(Source):
    name = "gradle"
    description = "Artifacts in the Gradle dependency cache (can be large; POM licenses)"
    registry = "maven"
    default_enabled = False

    def _root(self) -> Path:
        return env_path("GRADLE_USER_HOME", Path.home() / ".gradle") / "caches" / "modules-2" / "files-2.1"

    def available(self) -> bool:
        return self._root().is_dir()

    def packages(self) -> Iterable[Package]:
        # files-2.1/<group>/<artifact>/<version>/<sha1>/<file>
        for version_dir in self._root().glob("*/*/*"):
            group, artifact = version_dir.parent.parent.name, version_dir.parent.name
            pom = next(version_dir.glob("*/*.pom"), None)
            yield self.pkg(f"{group}:{artifact}", version_dir.name, meta.pom_licenses(pom) if pom else None)


# SDKMAN! Java identifiers end in a vendor code; these vendors' builds are not free.
NONFREE_JAVA_VENDORS = {"oracle": "Oracle JDK (Oracle No-Fee Terms)", "graal": "Oracle GraalVM (GFTC license)"}


class Sdkman(Source):
    name = "sdkman"
    description = "SDKMAN! candidates (Java vendor builds classified by vendor)"

    def _root(self) -> Path:
        return env_path("SDKMAN_DIR", Path.home() / ".sdkman") / "candidates"

    def available(self) -> bool:
        return self._root().is_dir()

    def packages(self) -> Iterable[Package]:
        for version_dir in self._root().glob("*/*"):
            if version_dir.name != "current" and version_dir.is_dir():
                yield self.pkg(version_dir.parent.name, version_dir.name)

    def verdict(self, package: Package) -> Finding | None:
        if package.name != "java":
            return None
        vendor = package.version.rsplit("-", 1)[-1]
        if vendor in NONFREE_JAVA_VENDORS:
            return Finding(
                package,
                Status.NONFREE,
                reason="sdkman vendor",
                description=NONFREE_JAVA_VENDORS[vendor],
                alternatives=("temurin (-tem)", "zulu", "graalce"),
            )
        return Finding(
            package, Status.FREE, reason="sdkman vendor", description="OpenJDK build (GPL-2.0 with Classpath exception)"
        )


class Coursier(Source):
    name = "coursier"
    description = "Scala/JVM apps installed with Coursier (`cs list`; names only)"

    def available(self) -> bool:
        return proc.which("cs") is not None or proc.which("coursier") is not None

    def packages(self) -> Iterable[Package]:
        tool = "cs" if proc.which("cs") else "coursier"
        for line in (proc.run([tool, "list"]) or "").splitlines():
            if line.strip():
                yield self.pkg(line.strip())
