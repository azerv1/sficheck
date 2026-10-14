from __future__ import annotations

from pathlib import Path

import httpx2

from sficheck.net import Fetcher


def serve(status: int, body: str = "") -> httpx2.MockTransport:
    return httpx2.MockTransport(lambda request: httpx2.Response(status, text=body))


def test_get_caches_the_body(tmp_path: Path) -> None:
    assert Fetcher(root=tmp_path, transport=serve(200, "hello")).get("https://x.test/a") == "hello"
    # A second fetcher would fail, but the fresh cached copy is used.
    assert Fetcher(root=tmp_path, transport=serve(500)).get("https://x.test/a") == "hello"
    assert Fetcher(root=tmp_path, offline=True).get("https://x.test/a") == "hello"


def test_missing_pages_and_errors(tmp_path: Path) -> None:
    assert Fetcher(root=tmp_path, transport=serve(404)).get("https://x.test/gone") is None
    Fetcher(root=tmp_path, transport=serve(200, "old")).get("https://x.test/b")
    assert Fetcher(root=tmp_path, refresh=True, transport=serve(503)).get("https://x.test/b") == "old"

    def unreachable(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("no route", request=request)

    flaky = Fetcher(root=tmp_path, refresh=True, transport=httpx2.MockTransport(unreachable))
    assert flaky.get("https://x.test/b") == "old"
    assert flaky.get("https://x.test/never") is None
    assert Fetcher(root=tmp_path, offline=True).get("https://x.test/never") is None


def test_only_https_is_fetched(tmp_path: Path) -> None:
    assert Fetcher(root=tmp_path, transport=serve(200, "list")).get("http://x.test/a") is None

    def downgrade(request: httpx2.Request) -> httpx2.Response:
        if request.url.scheme == "https":
            return httpx2.Response(302, headers={"Location": "http://x.test/plain"})
        return httpx2.Response(200, text="swapped")

    assert Fetcher(root=tmp_path, transport=httpx2.MockTransport(downgrade)).get("https://x.test/b") is None
