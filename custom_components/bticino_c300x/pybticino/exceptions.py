"""Exceptions for the Bticino C300X integration."""


class BticinoError(Exception):
    """Base exception."""


class BticinoAuthError(BticinoError):
    """Authentication failed (wrong credentials, expired token, etc.)."""


class BticinoConnectionError(BticinoError):
    """Cannot reach the server (cloud or local gateway)."""


class BticinoApiError(BticinoError):
    """API returned an unexpected response."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class BticinoSipError(BticinoError):
    """SIP registration or message delivery failed."""


class BticinoSipAuthError(BticinoSipError):
    """SIP digest authentication failed."""


class BticinoOwnError(BticinoError):
    """OWN protocol (local TCP) error."""


class BticinoGatewayNotFound(BticinoError):
    """Gateway not reachable or not found on the local network."""
