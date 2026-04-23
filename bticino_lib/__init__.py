"""Bticino C300X embedded library.

Public API used by the Home Assistant integration:

  from .bticino_lib import BticinoApiClient   # cloud, config flow only
  from .bticino_lib import BticinoOwnClient   # local, runtime
  from .bticino_lib.models import DeviceInfo, GatewayInfo, PlantInfo
  from .bticino_lib.exceptions import BticinoAuthError, BticinoConnectionError
"""

from .exceptions import (
    BticinoApiError,
    BticinoAuthError,
    BticinoConnectionError,
    BticinoError,
    BticinoOwnError,
)
from .models import DeviceInfo, GatewayInfo, PlantInfo
from .protocol import BticinoApiClient, BticinoOwnClient

__all__ = [
    "BticinoApiClient",
    "BticinoOwnClient",
    "DeviceInfo",
    "GatewayInfo",
    "PlantInfo",
    "BticinoError",
    "BticinoApiError",
    "BticinoAuthError",
    "BticinoConnectionError",
    "BticinoOwnError",
]
