"""Tests for the fixture that requires every mocked response to be used."""

import re

import aiohttp
from aiointercept import MockResponse, aiointercept

from .conftest import unused_responses

URL_STATUS = "http://example.com:3000/control/status"


async def request(*urls: str) -> None:
    """Send a GET request to each URL."""
    async with aiohttp.ClientSession() as session:
        for url in urls:
            async with session.get(url) as response:
                await response.read()


async def test_used_response() -> None:
    """Test a response that served a request counts as used."""
    async with aiointercept(mock_external_urls=True) as mocker:
        mocked = [("GET status", mocker.get(URL_STATUS, payload={}))]

        await request(URL_STATUS)

        assert unused_responses(mocked) == []


async def test_unrequested_response() -> None:
    """Test a response without a request counts as unused."""
    async with aiointercept(mock_external_urls=True) as mocker:
        mocked = [("GET status", mocker.get(URL_STATUS, payload={}))]

        assert unused_responses(mocked) == ["GET status"]


async def test_two_responses_one_request() -> None:
    """Test one request uses only one of two responses for the same URL."""
    async with aiointercept(mock_external_urls=True) as mocker:
        mocked: list[tuple[str, MockResponse]] = [
            ("first", mocker.get(URL_STATUS, payload={})),
            ("second", mocker.get(URL_STATUS, payload={})),
        ]

        await request(URL_STATUS)

        assert unused_responses(mocked) == ["second"]


async def test_response_replaced_by_repeating_one() -> None:
    """Test a response replaced by a repeating one counts as unused.

    aiointercept does not queue a response with repeat=True behind earlier ones
    for the same URL, it replaces them. The earlier one never serves anything.
    """
    async with aiointercept(mock_external_urls=True) as mocker:
        mocked = [
            ("three times", mocker.get(URL_STATUS, payload={}, repeat=3)),
            ("forever", mocker.get(URL_STATUS, payload={}, repeat=True)),
        ]

        await request(URL_STATUS, URL_STATUS, URL_STATUS)

        assert unused_responses(mocked) == ["three times"]


async def test_repeating_response_used_once() -> None:
    """Test a response that repeats counts as used after a single request."""
    async with aiointercept(mock_external_urls=True) as mocker:
        mocked = [("forever", mocker.get(URL_STATUS, payload={}, repeat=True))]

        await request(URL_STATUS)

        assert unused_responses(mocked) == []


async def test_overlapping_patterns() -> None:
    """Test one request uses only one of two patterns it matches."""
    async with aiointercept(mock_external_urls=True) as mocker:
        mocked = [
            ("control", mocker.get(re.compile(r"^http://example\.com:3000/control/"))),
            ("status", mocker.get(re.compile(r".*/status$"))),
        ]

        await request(URL_STATUS)

        assert len(unused_responses(mocked)) == 1


async def test_reordered_query_parameters() -> None:
    """Test one request uses only one of two URLs that differ in query order."""
    async with aiointercept(mock_external_urls=True) as mocker:
        mocked = [
            ("a then b", mocker.get(f"{URL_STATUS}?a=1&b=2", payload={})),
            ("b then a", mocker.get(f"{URL_STATUS}?b=2&a=1", payload={})),
        ]

        await request(f"{URL_STATUS}?a=1&b=2")

        assert len(unused_responses(mocked)) == 1
