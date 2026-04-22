"""Bticino C300X Python library.

Public interface::

    from bticino_c300x import BticinoGateway, BticinoApiClient
    from bticino_c300x.models import GatewayConfig, SipCredentials
    from bticino_c300x.exceptions import BticinoAuthError, BticinoSipError
"""

from .api import BticinoApiClient
from .auth import BticinoAuth
from .exceptions import (
    BticinoApiError,
    BticinoAuthError,
    BticinoConnectionError,
    BticinoError,
    BticinoGatewayNotFound,
    BticinoOwnError,
    BticinoSipAuthError,
    BticinoSipError,
)
from .gateway import BticinoGateway
from .models import (
    DeviceInfo,
    GatewayConfig,
    GatewayInfo,
    PlantInfo,
    SipCredentials,
    TlsCertificates,
    UserInfo,
)
from .own import BticinoOwnClient
from .sip import BticinoSipClient

__all__ = [
    "BticinoAuth",
    "BticinoApiClient",
    "BticinoGateway",
    "BticinoSipClient",
    "BticinoOwnClient",
    # models
    "DeviceInfo",
    "GatewayConfig",
    "GatewayInfo",
    "PlantInfo",
    "SipCredentials",
    "TlsCertificates",
    "UserInfo",
    # exceptions
    "BticinoError",
    "BticinoAuthError",
    "BticinoConnectionError",
    "BticinoApiError",
    "BticinoSipError",
    "BticinoSipAuthError",
    "BticinoOwnError",
    "BticinoGatewayNotFound",
]
