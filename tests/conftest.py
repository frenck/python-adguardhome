"""Common fixtures and helpers for AdGuard Home tests."""

import json
from collections.abc import AsyncGenerator, Callable
from pathlib import Path
from re import Pattern
from typing import Any

import aiohttp
import pytest
from aiointercept import aiointercept
from yarl import URL

from adguardhome import AdGuardHome

FIXTURES_DIR = Path(__file__).parent / "fixtures"

FixtureLoader = Callable[[str], Any]


@pytest.fixture
def load_fixture() -> FixtureLoader:
    """Return a helper that loads a JSON fixture by name."""

    def _load(name: str) -> Any:
        return json.loads((FIXTURES_DIR / f"{name}.json").read_text(encoding="utf-8"))

    return _load


@pytest.fixture
async def responses() -> AsyncGenerator[aiointercept, None]:
    """Yield an aiointercept instance that intercepts aiohttp client requests.

    Every mocked route must be requested by the test. Many tests assert the
    request inside a callback, and without this check, such a test would pass
    when the code under test never sends the request at all.
    """
    async with aiointercept(mock_external_urls=True) as mocker:
        registered: list[tuple[str, str | URL | Pattern[str]]] = []
        add = mocker.add

        def add_and_remember(
            url: str | URL | Pattern[str], method: str = "GET", **kwargs: Any
        ) -> Any:
            registered.append((method.upper(), url))
            return add(url, method, **kwargs)

        mocker.add = add_and_remember  # ty: ignore[invalid-assignment]
        yield mocker

        requested = list(mocker.requests)
        unused = [
            f"{method} {url}"
            for method, url in registered
            if not any(
                method == requested_method and _matches(url, requested_url)
                for requested_method, requested_url in requested
            )
        ]
        assert not unused, f"Mocked, but never requested: {unused}"


def _matches(url: str | URL | Pattern[str], requested: URL) -> bool:
    """Return if a request went to a mocked URL or URL pattern."""
    if isinstance(url, Pattern):
        return url.match(str(requested)) is not None

    # Like aiointercept itself, ignore the order of the query parameters.
    mocked = URL(url)
    return mocked.with_query(None) == requested.with_query(None) and sorted(
        mocked.query.items()
    ) == sorted(requested.query.items())


@pytest.fixture
async def adguard() -> AsyncGenerator[AdGuardHome, None]:
    """Yield an AdGuardHome client wired to example.com with default settings."""
    async with aiohttp.ClientSession() as session:
        yield AdGuardHome("http://example.com:3000", session=session)
