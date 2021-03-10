"""Exceptions for AdGuard Home."""


class AdGuardHomeError(Exception):
    """Generic AdGuard Home exception."""


class AdGuardHomeConnectionError(AdGuardHomeError):
    """AdGuard Home connection exception."""
