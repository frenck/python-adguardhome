# pylint: disable=W0621
"""Asynchronous Python client for the AdGuard Home API."""

import asyncio

from adguardhome import AdGuardHome


async def main() -> None:
    """Show example on controlling your AdGuard Home instance."""
    async with AdGuardHome("http://192.168.1.2:3000") as adguard:
        status = await adguard.status()
        print("AdGuard version:", status.version)

        print("Turning off protection...")
        await adguard.disable_protection()

        status = await adguard.status()
        yes_no = "Yes" if status.protection_enabled else "No"
        print("Protection enabled?", yes_no)

        print("Turning on protection")
        await adguard.enable_protection()

        status = await adguard.status()
        yes_no = "Yes" if status.protection_enabled else "No"
        print("Protection enabled?", yes_no)


if __name__ == "__main__":
    asyncio.run(main())
