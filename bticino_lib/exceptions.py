"""Exceptions for the Bticino C300X library."""


class BticinoError(Exception):
    """Base exception."""


class BticinoConnectionError(BticinoError):
    """Cannot reach the cloud portal or the local gateway."""


class BticinoAuthError(BticinoError):
    """Authentication failure (wrong credentials or expired token)."""


class BticinoApiError(BticinoError):
    """Unexpected API response."""

    def __init__(self, message: str, status_code: int = 0) -> None:
        super().__init__(message)
        self.status_code = status_code


class BticinoOwnError(BticinoError):
    """Error communicating with the gateway via OWN local protocol."""


class BticinoSipError(BticinoError):
    """Error communicating via SIP."""


class BticinoSipAuthError(BticinoSipError):
    """SIP digest authentication failed."""
