"""Common fixtures and helpers for AdGuard Home tests."""

import json
from collections.abc import AsyncGenerator, Callable, Generator
from pathlib import Path
from typing import Any

import aiohttp
import pytest
from aioresponses import aioresponses

from adguardhome import AdGuardHome

FIXTURES_DIR = Path(__file__).parent / "fixtures"

FixtureLoader = Callable[[str], Any]


@pytest.fixture
def load_fixture() -> FixtureLoader:
    """Return a helper that loads a JSON fixture by name."""

    def _load(name: str) -> Any:
        return json.loads((FIXTURES_DIR / f"{name}.json").read_text())

    return _load


@pytest.fixture
def responses() -> Generator[aioresponses, None, None]:
    """Yield an aioresponses instance that patches aiohttp client sessions."""
    with aioresponses() as mocker:
        yield mocker


@pytest.fixture
async def adguard() -> AsyncGenerator[AdGuardHome, None]:
    """Yield an AdGuardHome client wired to example.com with default settings."""
    async with aiohttp.ClientSession() as session:
        yield AdGuardHome("example.com", session=session)
