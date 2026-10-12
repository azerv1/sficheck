"""HTTP fetching with an on-disk cache, so repeated runs and --offline work."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sficheck import __version__

log = logging.getLogger(__name__)

USER_AGENT = f"sficheck/{__version__} (+https://github.com/azerv1/sficheck)"


def cache_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "sficheck"


@dataclass(slots=True)
class Fetcher:
    """Fetches URLs, caching bodies for ``ttl`` seconds.

    offline: never touch the network, use whatever is cached (even if stale).
    refresh: ignore the TTL and always refetch (stale cache is still a fallback).
    """

    ttl: float = 24 * 3600
    offline: bool = False
    refresh: bool = False
    timeout: float = 30
    root: Path | None = None
    transport: Any = None  # an httpx2 transport; tests pass httpx2.MockTransport

    def _path(self, key: str, kind: str = "http") -> Path:
        digest = hashlib.sha256(key.encode()).hexdigest()[:32]
        return (self.root or cache_dir()) / kind / digest

    def _cached(self, path: Path) -> tuple[str | None, bool]:
        """(cached body, whether it can be used without refetching)."""
        if not path.is_file():
            return None, False
        body = path.read_text(encoding="utf-8")
        fresh = time.time() - path.stat().st_mtime < self.ttl
        return body, self.offline or (fresh and not self.refresh)

    def memo(self, key: str, produce: Callable[[], str | None]) -> str | None:
        """Cache the result of a slow local command (e.g. ``winget show``) like an HTTP body."""
        path = self._path(key, "memo")
        cached, usable = self._cached(path)
        if usable or self.offline:
            return cached
        body = produce()
        if body is None:
            return cached
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return body

    def get(self, url: str) -> str | None:
        path = self._path(url)
        cached, usable = self._cached(path)
        if usable or self.offline:
            return cached
        import httpx2  # only runs that go online pay for the import

        headers = {"User-Agent": USER_AGENT}
        try:
            with httpx2.Client(
                headers=headers, timeout=self.timeout, follow_redirects=True, transport=self.transport
            ) as client:
                response = client.get(url)
            if response.status_code == 404:
                return None
            response.raise_for_status()
        except httpx2.HTTPError as exc:
            log.warning("Could not download %s (%s)%s", url, exc, "; using cached copy" if cached else "")
            return cached
        body = response.text
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return body

    def get_json(self, url: str) -> object | None:
        body = self.get(url)
        if body is None:
            return None
        try:
            parsed: object = json.loads(body)
        except json.JSONDecodeError:
            return None
        return parsed
