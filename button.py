"""Button entities for Bticino C300X — local OWN protocol only."""

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
from .bticino_lib.const import CID_STANDARD, DTMF_CLOSE_ALT, DTMF_CLOSE_STD, DTMF_OPEN_ALT, DTMF_OPEN_STD
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
    """A button that sends an OWN activation command to the gateway."""

    _attr_has_entity_name = True

    def __init__(self, own_params: dict, device: dict, entry_id: str) -> None:
        self._own_params = own_params
        self._device = device

        cid = device["cid"]
        addr = device["addr"]
        dev = device.get("dev", "2")
        where = f"{dev}{addr}"
        self._attr_unique_id = f"{entry_id}_{cid}_{addr}"
        self._attr_name = device.get("name", f"Attivazione {cid}")
        _LOGGER.debug("Button '%s' frames: open=%s close=%s (dev=%r addr=%r where=%r)",
                      self._attr_name,
                      f"{DTMF_OPEN_STD if cid in CID_STANDARD else DTMF_OPEN_ALT}*{where}##",
                      f"{DTMF_CLOSE_STD if cid in CID_STANDARD else DTMF_CLOSE_ALT}*{where}##",
                      dev, addr, where)

        if cid in CID_STANDARD:
            self._frame_open = f"{DTMF_OPEN_STD}*{where}##"
            self._frame_close = f"{DTMF_CLOSE_STD}*{where}##"
        else:
            self._frame_open = f"{DTMF_OPEN_ALT}*{where}##"
            self._frame_close = f"{DTMF_CLOSE_ALT}*{where}##"

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
        """Send open + close OWN frames to the gateway.

        The gateway closes the TCP connection after each command, so each
        frame needs its own connection (full handshake + *99*0## each time).
        """
        local_ip = self._own_params["local_ip"]
        password = self._own_params["own_password"]

        _LOGGER.info(
            "Button '%s' pressed — connecting to %s, will send %s then %s",
            self._attr_name, local_ip, self._frame_open, self._frame_close,
        )

        try:
            _LOGGER.info("Button '%s' — connection 1/2: sending %s", self._attr_name, self._frame_open)
            async with BticinoOwnClient(local_ip, password) as client:
                resp1 = await client.send_raw(self._frame_open)
            _LOGGER.info("Button '%s' — connection 1/2 OK, gateway replied: %s", self._attr_name, resp1)

            await asyncio.sleep(0.3)

            _LOGGER.info("Button '%s' — connection 2/2: sending %s", self._attr_name, self._frame_close)
            async with BticinoOwnClient(local_ip, password) as client:
                resp2 = await client.send_raw(self._frame_close)
            _LOGGER.info("Button '%s' — connection 2/2 OK, gateway replied: %s", self._attr_name, resp2)

            _LOGGER.info("Button '%s' — sequence completed successfully", self._attr_name)

        except BticinoOwnError as exc:
            _LOGGER.error(
                "Button '%s' — OWN error at %s: %s",
                self._attr_name, local_ip, exc,
            )
            raise
