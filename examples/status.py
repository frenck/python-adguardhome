# pylint: disable=W0621
"""Asynchronous Python client for the AdGuard Home API."""

import asyncio

from adguardhome import AdGuardHome


async def main() -> None:
    """Show example how to get status of your AdGuard Home instance."""
    async with AdGuardHome(host="192.168.1.2") as adguard:
        version = await adguard.version()
        print("AdGuard version:", version)

        active = await adguard.protection_enabled()
        yes_no = "Yes" if active else "No"
        print("Protection enabled?", yes_no)

        active = await adguard.filtering.enabled()
        yes_no = "Yes" if active else "No"
        print("Filtering enabled?", yes_no)

        active = await adguard.parental.enabled()
        yes_no = "Yes" if active else "No"
        print("Parental control enabled?", yes_no)

        active = await adguard.safebrowsing.enabled()
        yes_no = "Yes" if active else "No"
        print("Safe browsing enabled?", yes_no)

        active = await adguard.safesearch.enabled()
        yes_no = "Yes" if active else "No"
        print("Enforce safe search enabled?", yes_no)


if __name__ == "__main__":
    asyncio.run(main())
