# -*- coding: utf-8 -*-
"""Exceptions for AdGuard Home."""


class AdGuardHomeError(Exception):
    """Generic AdGuard Home exception."""

    pass


class AdGuardHomeConnectionError(AdGuardHomeError):
    """AdGuard Home connection exception."""

    pass
