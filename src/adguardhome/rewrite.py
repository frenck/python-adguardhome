"""Asynchronous Python client for the AdGuard Home API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .exceptions import AdGuardHomeError

if TYPE_CHECKING:
    from . import AdGuardHome


@dataclass
class AdGuardHomeRewrite:
    """Controls AdGuard Home DNS rewrites."""

    adguard: AdGuardHome

    async def list(self) -> list[dict[str, str]]:
        """Return all defined DNS rewrites.

        Returns:
            A list of all defined DNS rewrites in the AdGuardHome instance.
            Each rewrite is represented as a dictionary with 'domain' and 'answer' keys.

        """
        return await self.adguard.request("rewrite/list")

    async def add(self, domain: str, answer: str) -> None:
        """Add a new DNS rewrite rule to AdGuard Home.

        Args:
        ----
            domain: The domain pattern to rewrite (e.g., "*.example.com").
            answer: The IP address or domain to rewrite to.

        Raises:
        ------
            AdGuardHomeError: Failed adding the DNS rewrite rule.

        """
        try:
            await self.adguard.request(
                "rewrite/add",
                method="POST",
                json_data={"domain": domain, "answer": answer},
            )
        except AdGuardHomeError as exception:
            msg = "Failed to add DNS rewrite rule to AdGuard Home"
            raise AdGuardHomeError(msg) from exception

    async def delete(self, domain: str, answer: str) -> None:
        """Delete a DNS rewrite rule from AdGuard Home.

        Args:
        ----
            domain: The domain pattern of the rewrite rule to delete.
            answer: The IP address or domain of the rewrite rule to delete.

        Raises:
        ------
            AdGuardHomeError: Failed to delete DNS rewrite rule.

        """
        try:
            await self.adguard.request(
                "rewrite/delete",
                method="POST",
                json_data={"domain": domain, "answer": answer},
            )
        except AdGuardHomeError as exception:
            msg = "Failed to delete DNS rewrite rule from AdGuard Home"
            raise AdGuardHomeError(msg) from exception
