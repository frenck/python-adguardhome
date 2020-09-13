"""Asynchronous Python client for the AdGuard Home API."""

from typing import List, Dict

from .exceptions import AdGuardHomeError


class AdGuardHomeRewrite:
    """Controls AdGuard Home DNS rewrites."""

    def __init__(self, adguard) -> None:
        """Initialise object."""
        self._adguard = adguard

    async def list(self) -> List[Dict[str, str]]:
        """Return all defined DNS rewrites."""
        response = await self._adguard._request("rewrite/list")
        return response

    async def add(self, domain: str, answer: str) -> None:
        """Add a new DNS rewrite rule to AdGuard Home."""
        response = await self._adguard._request(
            "rewrite/add", method="POST", json_data={"domain": domain, "answer": answer}
        )
        if response != "":
            raise AdGuardHomeError(
                "Failed to add DNS rewrite rule to AdGuard Home", {"response": response}
            )

    async def delete(self, domain: str, answer: str) -> None:
        """Delete a DNS rewrite rule from AdGuard Home."""
        response = await self._adguard._request(
            "rewrite/delete",
            method="POST",
            json_data={"domain": domain, "answer": answer},
        )
        if response != "":
            raise AdGuardHomeError(
                "Failed to delete DNS rewrite rule from AdGuard Home",
                {"response": response},
            )
