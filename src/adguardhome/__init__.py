"""Asynchronous Python client for the AdGuard Home API."""

from .adguardhome import AdGuardHome
from .client import AutoClient, Client
from .exceptions import AdGuardHomeConnectionError, AdGuardHomeError

__all__ = [
    "AdGuardHome",
    "AdGuardHomeConnectionError",
    "AdGuardHomeError",
    "AutoClient",
    "Client",
]
