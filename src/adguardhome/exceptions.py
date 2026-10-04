"""Exceptions for AdGuard Home."""

from __future__ import annotations


class AdGuardHomeError(Exception):
    """Generic AdGuard Home exception."""


class AdGuardHomeConnectionError(AdGuardHomeError):
    """AdGuard Home could not be reached."""


class AdGuardHomeConnectionTimeoutError(AdGuardHomeConnectionError):
    """AdGuard Home did not respond in time."""


class AdGuardHomeAuthenticationError(AdGuardHomeError):
    """AdGuard Home rejected the credentials."""


class AdGuardHomeResponseError(AdGuardHomeError):
    """AdGuard Home returned an error response."""

    def __init__(self, message: str, *, status: int, body: str) -> None:
        """Initialize the exception with the status and body of the response.

        Args:
        ----
            message: Human readable description of the error.
            status: The HTTP status code AdGuard Home responded with.
            body: The response body, which AdGuard Home uses for its
                error message.

        """
        super().__init__(message)
        self.status = status
        self.body = body


class AdGuardHomeUnsupportedError(AdGuardHomeResponseError):
    """AdGuard Home does not support the requested API.

    On this API, an unknown endpoint nearly always means the AdGuard Home
    instance is older than the minimum version this library supports.
    """
