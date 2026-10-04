# pylint: disable=W0621
"""Asynchronous Python client for the AdGuard Home API."""

import asyncio

from adguardhome import AdGuardHome


async def main() -> None:
    """Show example how to get status of your AdGuard Home instance."""
    async with AdGuardHome("http://192.168.1.2:3000") as adguard:
        status = await adguard.status()
        print("AdGuard version:", status.version)

        yes_no = "Yes" if status.protection_enabled else "No"
        print("Protection enabled?", yes_no)

        filtering = await adguard.filtering.config()
        yes_no = "Yes" if filtering.enabled else "No"
        print("Filtering enabled?", yes_no)

        active = await adguard.parental.enabled()
        yes_no = "Yes" if active else "No"
        print("Parental control enabled?", yes_no)

        active = await adguard.safebrowsing.enabled()
        yes_no = "Yes" if active else "No"
        print("Safe browsing enabled?", yes_no)

        safesearch = await adguard.safesearch.config()
        yes_no = "Yes" if safesearch.enabled else "No"
        print("Enforce safe search enabled?", yes_no)


if __name__ == "__main__":
    asyncio.run(main())
