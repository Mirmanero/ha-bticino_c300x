"""Button entities for Bticino C300X — local OWN protocol only."""

from __future__ import annotations

import asyncio
import logging

from homeassistant.components.button import ButtonEntity, ButtonDeviceClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo as HaDeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    CID_ALT,
    CID_STANDARD,
    DATA_DEVICES,
    DATA_OWN_PARAMS,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

_DTMF_OPEN_STD = "*8*19"
_DTMF_CLOSE_STD = "*8*20"
_DTMF_OPEN_ALT = "*8*21"
_DTMF_CLOSE_ALT = "*8*22"

_ICON_LOCK = "mdi:lock-open-variant"
_ICON_GATE = "mdi:gate"
_ICON_RELAY = "mdi:toggle-switch"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up button entities from stored device list."""
    data = hass.data[DOMAIN][entry.entry_id]
    own_params = data[DATA_OWN_PARAMS]
    devices = data[DATA_DEVICES]

    entities = [
        BticinoButton(own_params, device, entry.entry_id)
        for device in devices
    ]
    async_add_entities(entities)


class BticinoButton(ButtonEntity):
    """A button that sends an OWN activation command to the gateway."""

    _attr_has_entity_name = True

    def __init__(self, own_params: dict, device: dict, entry_id: str) -> None:
        self._own_params = own_params
        self._device = device
        self._entry_id = entry_id

        cid = device["cid"]
        addr = device["addr"]
        self._attr_unique_id = f"{entry_id}_{cid}_{addr}"
        self._attr_name = device.get("name", f"Attivazione {cid}")

        if cid in CID_STANDARD:
            self._frame_open = f"{_DTMF_OPEN_STD}*{addr}##"
            self._frame_close = f"{_DTMF_CLOSE_STD}*{addr}##"
        else:
            self._frame_open = f"{_DTMF_OPEN_ALT}*{addr}##"
            self._frame_close = f"{_DTMF_CLOSE_ALT}*{addr}##"

    @property
    def icon(self) -> str:
        cid = self._device["cid"]
        name = (self._device.get("name") or "").lower()
        if "serratura" in name or "lock" in name:
            return _ICON_LOCK
        if "cancello" in name or "gate" in name or "porta" in name:
            return _ICON_GATE
        if cid in CID_STANDARD:
            return _ICON_LOCK
        return _ICON_RELAY

    @property
    def device_info(self) -> HaDeviceInfo:
        return HaDeviceInfo(
            identifiers={(DOMAIN, self._entry_id)},
            name="Bticino C300X",
            manufacturer="Bticino / Legrand",
            model="C300X",
        )

    async def async_press(self) -> None:
        """Send open + close OWN frames to the gateway."""
        from .pybticino.own import BticinoOwnClient
        from .pybticino.exceptions import BticinoOwnError

        local_ip = self._own_params["local_ip"]
        password = self._own_params["own_password"]

        _LOGGER.debug(
            "Button '%s' pressed — sending %s then %s to %s",
            self._attr_name, self._frame_open, self._frame_close, local_ip,
        )

        try:
            async with BticinoOwnClient(local_ip, password) as client:
                await client.send_raw(self._frame_open)
                await asyncio.sleep(0.3)
                await client.send_raw(self._frame_close)
        except BticinoOwnError as exc:
            _LOGGER.error("OWN command failed for '%s': %s", self._attr_name, exc)
            raise
