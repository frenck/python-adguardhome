"""Asynchronous Python client for the AdGuard Home API."""

from .exceptions import AdGuardHomeError


class AdGuardHomeClient:
    """Controls AdGuard Home client settings."""

    def __init__(self, adguard):
        """Initilaze object."""
        self._adguard = adguard

    async def _client_settings(self, ip: str):
        response = await self._adguard._request("clients/find", params={"ip0": ip})
        if len(response) != 1:
            raise AdGuardHomeError("Client not found", {"response": response})
        return response

    async def _client_update(self, data: dict):
        await self._adguard._request(
            "clients/update",
            method="POST",
            json_data={"data": data, "name": data["name"]},
        )

    async def allow_service(self, ip: str, service: str) -> None:
        """Allow ip to access service."""
        response = await self._client_settings(ip)
        if response:
            data = response[0][ip]
            if service in data["blocked_services"]:
                data["blocked_services"].remove(service)
                await self._client_update(data)

    async def block_service(self, ip: str, service: str) -> None:
        """Block ip from accessing service."""
        response = await self._client_settings(ip)
        if response:
            data = response[0][ip]
            if service not in data["blocked_services"]:
                data["blocked_services"].append(service)
                await self._client_update(data)
