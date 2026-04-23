"""Bticino C300X Home Assistant integration.

Works local-only via OWN protocol after initial cloud setup.
"""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import (
    CONF_DEVICES,
    CONF_GATEWAY_ID,
    CONF_LOCAL_IP,
    CONF_OWN_PASSWORD,
    DATA_DEVICES,
    DATA_OWN_PARAMS,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["button"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Bticino C300X from a config entry (no cloud calls at runtime)."""
    hass.data.setdefault(DOMAIN, {})

    hass.data[DOMAIN][entry.entry_id] = {
        DATA_OWN_PARAMS: {
            "local_ip": entry.data[CONF_LOCAL_IP],
            "own_password": entry.data[CONF_OWN_PASSWORD],
            "gateway_id": entry.data[CONF_GATEWAY_ID],
        },
        DATA_DEVICES: entry.data.get(CONF_DEVICES, []),
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok
