"""Asynchronous Python client for the AdGuard Home API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, TYPE_CHECKING

from .exceptions import AdGuardHomeError

if TYPE_CHECKING:
    from . import AdGuardHome


@dataclass
class AdGuardHomeRewrite:
    """Controls AdGuard Home DNS rewrites."""

    adguard: AdGuardHome

    async def list(self) -> List[Dict[str, str]]:
        """Return all defined DNS rewrites."""
        response = await self.adguard.request("rewrite/list")
        return response

    async def add(self, domain: str, answer: str) -> None:
        """Add a new DNS rewrite rule to AdGuard Home."""
        response = await self.adguard.request(
            "rewrite/add", method="POST", json_data={"domain": domain, "answer": answer}
        )
        if response != "":
            raise AdGuardHomeError(
                "Failed to add DNS rewrite rule to AdGuard Home", {"response": response}
            )

    async def delete(self, domain: str, answer: str) -> None:
        """Delete a DNS rewrite rule from AdGuard Home."""
        response = await self.adguard.request(
            "rewrite/delete",
            method="POST",
            json_data={"domain": domain, "answer": answer},
        )
        if response != "":
            raise AdGuardHomeError(
                "Failed to delete DNS rewrite rule from AdGuard Home",
                {"response": response},
            )
