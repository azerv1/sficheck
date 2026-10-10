"""HTTP fetching with an on-disk cache, so repeated runs and --offline work."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from absolutely_proprietary import __version__

log = logging.getLogger(__name__)

USER_AGENT = f"absolutely-proprietary/{__version__} (+https://github.com/vmavromatis/absolutely-proprietary)"


def cache_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "absolutely-proprietary"


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
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                body: str = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            log.warning("Could not download %s (%s)%s", url, exc, "; using cached copy" if cached else "")
            return cached
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            log.warning("Could not download %s (%s)%s", url, exc, "; using cached copy" if cached else "")
            return cached
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
