# -*- coding: utf-8 -*-
# pylint: disable=W0621
"""Asynchronous Python client for the AdGuard Home API."""

import asyncio

from adguardhome import AdGuardHome


async def main():
    """Show example on controlling your AdGuard Home instance."""
    async with AdGuardHome("192.168.1.2") as adguard:
        version = await adguard.version()
        print("AdGuard version:", version)

        print("Turning off protection...")
        await adguard.disable_protection()

        active = await adguard.protection_enabled()
        active = "Yes" if active else "No"
        print("Protection enabled?", active)

        print("Turning on protection")
        await adguard.enable_protection()

        active = await adguard.protection_enabled()
        active = "Yes" if active else "No"
        print("Protection enabled?", active)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
