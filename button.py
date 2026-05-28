"""Button entities for Bticino C300X — door activation via OWN local protocol."""

from __future__ import annotations

import asyncio
import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo as HaDeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .bticino_lib import BticinoOwnClient
from .bticino_lib.exceptions import BticinoOwnError
from .bticino_lib.const import (
    CID_STANDARD,
    DTMF_CLOSE_ALT,
    DTMF_CLOSE_STD,
    DTMF_OPEN_ALT,
    DTMF_OPEN_STD,
    OWN_DEFAULT_PORT,
)
from .const import DATA_DEVICES, DATA_OWN_PARAMS, DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up button entities from the stored device list."""
    data = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        BticinoButton(data[DATA_OWN_PARAMS], device, entry.entry_id)
        for device in data[DATA_DEVICES]
    )


class BticinoButton(ButtonEntity):
    """A button that sends door-activation OWN frames via local TCP."""

    _attr_has_entity_name = True

    def __init__(
        self,
        own_params: dict,
        device: dict,
        entry_id: str,
    ) -> None:
        self._own_params = own_params
        self._device = device

        cid = device["cid"]
        addr = device["addr"]   # OWN bus address from XML, e.g. "0", "1"
        self._attr_unique_id = f"{entry_id}_{cid}_{addr}"
        self._attr_name = device.get("name", f"Attivazione {cid}")

        if cid in CID_STANDARD:
            self._frame_open  = f"{DTMF_OPEN_STD}*{addr}##"
            self._frame_close = f"{DTMF_CLOSE_STD}*{addr}##"
        else:
            self._frame_open  = f"{DTMF_OPEN_ALT}*{addr}##"
            self._frame_close = f"{DTMF_CLOSE_ALT}*{addr}##"

        _LOGGER.debug(
            "Button '%s' configured: open=%s close=%s",
            self._attr_name, self._frame_open, self._frame_close,
        )

    @property
    def icon(self) -> str:
        name = (self._device.get("name") or "").lower()
        if "serratura" in name or "lock" in name:
            return "mdi:lock-open-variant"
        if "cancello" in name or "gate" in name or "porta" in name:
            return "mdi:gate"
        return "mdi:toggle-switch"

    @property
    def device_info(self) -> HaDeviceInfo:
        return HaDeviceInfo(
            identifiers={(DOMAIN, self._own_params["gateway_id"])},
            name="Bticino C300X",
            manufacturer="Bticino / Legrand",
            model="C300X",
        )

    async def async_press(self) -> None:
        """Send open + close OWN frames via local TCP."""
        local_ip = self._own_params.get("local_ip", "")
        own_password = self._own_params.get("own_password", "")

        if not local_ip:
            _LOGGER.error(
                "Button '%s' — local_ip not configured, cannot open door.",
                self._attr_name,
            )
            return

        _LOGGER.info(
            "Button '%s' — OWN %s → %s then %s",
            self._attr_name, local_ip, self._frame_open, self._frame_close,
        )

        try:
            async with BticinoOwnClient(
                host=local_ip,
                password=own_password,
                port=OWN_DEFAULT_PORT,
            ) as client:
                await client.send_raw(self._frame_open)
                await asyncio.sleep(0.3)
                await client.send_raw(self._frame_close)

            _LOGGER.info("Button '%s' — OWN sequence completed", self._attr_name)

        except BticinoOwnError as exc:
            _LOGGER.error("Button '%s' — OWN error: %s", self._attr_name, exc)
            raise
