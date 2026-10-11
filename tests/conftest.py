from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest
from hypothesis import settings

from absolutely_proprietary import proc
from absolutely_proprietary.net import Fetcher
from absolutely_proprietary.sources.base import Context

FakeRun = Callable[[dict[str, str | None]], None]

# No per-example deadline: shared CI runners (Windows especially) stall at random. CI explores harder.
settings.register_profile("default", deadline=None)
settings.register_profile("ci", deadline=None, max_examples=500)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci" if os.environ.get("CI") else "default"))


class StubFetcher(Fetcher):
    """Serves canned bodies by URL substring; never touches the network."""

    def __init__(self, root: Path, bodies: dict[str, str] | None = None) -> None:
        super().__init__(root=root, offline=True)
        self.bodies = bodies or {}

    def get(self, url: str) -> str | None:
        return next((body for key, body in self.bodies.items() if key in url), None)


@pytest.fixture
def fetcher(tmp_path: Path) -> StubFetcher:
    return StubFetcher(tmp_path / "cache")


@pytest.fixture
def ctx(fetcher: StubFetcher) -> Context:
    return Context(fetcher=fetcher, jobs=2)


@pytest.fixture
def fake_run(monkeypatch: pytest.MonkeyPatch) -> FakeRun:
    """Map a command prefix (space-joined) to its stdout; unmatched commands "aren't installed"."""

    def install(outputs: dict[str, str | None]) -> None:
        def run(cmd: list[str], timeout: float = 0, ok_codes: tuple[int, ...] = (0,)) -> str | None:
            joined = " ".join(cmd)
            for prefix in sorted(outputs, key=len, reverse=True):
                if joined.startswith(prefix):
                    return outputs[prefix]
            return None

        tools = {prefix.split()[0] for prefix in outputs}
        monkeypatch.setattr(proc, "run", run)
        monkeypatch.setattr(proc, "which", lambda tool: f"/usr/bin/{tool}" if tool in tools else None)

    return install
