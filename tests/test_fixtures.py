"""Tests for the fixture that requires every mocked response to be used."""

import re
from types import SimpleNamespace
from typing import Any

import pytest
from yarl import URL

from .conftest import _unused

URL_STATUS = "http://example.com:3000/control/status"


def mocker(requests: dict[tuple[str, str], int]) -> Any:
    """Return a stand-in for aiointercept that made these requests."""
    return SimpleNamespace(
        requests={
            (method, URL(url)): [object()] * count
            for (method, url), count in requests.items()
        }
    )


@pytest.mark.parametrize(
    ("registered", "requests", "unused"),
    [
        ([("GET", URL_STATUS, False)], {("GET", URL_STATUS): 1}, 0),
        ([("GET", URL_STATUS, False)], {}, 1),
        ([("GET", URL_STATUS, False)], {("POST", URL_STATUS): 1}, 1),
        # Two responses for the same route need two requests.
        (
            [("GET", URL_STATUS, False), ("GET", URL_STATUS, False)],
            {("GET", URL_STATUS): 1},
            1,
        ),
        (
            [("GET", URL_STATUS, False), ("GET", URL_STATUS, False)],
            {("GET", URL_STATUS): 2},
            0,
        ),
        # A response that repeats needs its count used up before the next one.
        (
            [("GET", URL_STATUS, 3), ("GET", URL_STATUS, True)],
            {("GET", URL_STATUS): 3},
            1,
        ),
        ([("GET", URL_STATUS, True)], {("GET", URL_STATUS): 5}, 0),
        # Patterns, and query parameters in any order.
        (
            [("GET", re.compile(r"^http://example\.com:3000/control/"), False)],
            {("GET", URL_STATUS): 1},
            0,
        ),
        (
            [("GET", f"{URL_STATUS}?a=1&b=2", False)],
            {("GET", f"{URL_STATUS}?b=2&a=1"): 1},
            0,
        ),
    ],
)
def test_unused(
    registered: list[tuple[str, Any, bool | int]],
    requests: dict[tuple[str, str], int],
    unused: int,
) -> None:
    """Test a mocked response counts as used only when a request needed it."""
    assert len(_unused(registered, mocker(requests))) == unused
