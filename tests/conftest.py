"""Common fixtures and helpers for AdGuard Home tests."""

import json
from collections.abc import AsyncGenerator, Callable
from pathlib import Path
from re import Pattern
from typing import Any

import aiohttp
import pytest
from aiointercept import MockResponse, aiointercept
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

    Every mocked response must serve a request. Many tests assert the request
    inside a callback, and without this check, such a test would pass when the
    code under test never sends the request at all.
    """
    async with aiointercept(mock_external_urls=True) as mocker:
        mocked: list[tuple[str, MockResponse]] = []
        add = mocker.add

        def add_and_remember(
            url: str | URL | Pattern[str], method: str = "GET", **kwargs: Any
        ) -> MockResponse:
            response = add(url, method, **kwargs)
            mocked.append((f"{method.upper()} {url}", response))
            return response

        mocker.add = add_and_remember  # ty: ignore[invalid-assignment]
        yield mocker

        assert not (unused := unused_responses(mocked)), (
            f"Mocked, but never requested: {unused}"
        )


def unused_responses(mocked: list[tuple[str, MockResponse]]) -> list[str]:
    """Return the mocked responses that served no request.

    aiointercept counts per response how often it served a request, so this
    also holds for overlapping URL patterns, or several responses for one URL.
    """
    return [route for route, response in mocked if not response.call_count]


@pytest.fixture
async def adguard() -> AsyncGenerator[AdGuardHome, None]:
    """Yield an AdGuardHome client wired to example.com with default settings."""
    async with aiohttp.ClientSession() as session:
        yield AdGuardHome("http://example.com:3000", session=session)
