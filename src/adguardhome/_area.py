"""Base for the feature areas of the AdGuard Home API."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping


class Requester(Protocol):  # pylint: disable=too-few-public-methods
    """Signature of the request method of the AdGuard Home client."""

    async def __call__(
        self,
        path: str,
        *,
        method: str = "GET",
        json: Any = None,
        params: Mapping[str, str] | None = None,
    ) -> Any:
        """Handle a request to the AdGuard Home API."""


class Area:  # pylint: disable=too-few-public-methods
    """A feature area of the AdGuard Home API, like filtering or stats.

    An area only gets the request method of the client, not the client
    itself. That keeps the areas independent of each other and of how
    the client connects.
    """

    __slots__ = ("_request",)

    def __init__(self, request: Requester) -> None:
        """Initialize the area.

        Args:
        ----
            request: The request method of the AdGuard Home client.

        """
        self._request = request
