"""Button entities for Bticino C300X — door activation via SIP MESSAGE."""

from __future__ import annotations

import asyncio
import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo as HaDeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .bticino_lib import BticinoSipClient
from .bticino_lib.exceptions import BticinoSipError
from .bticino_lib.models import SipCredentials
from .bticino_lib.const import CID_STANDARD, DTMF_CLOSE_ALT, DTMF_CLOSE_STD, DTMF_OPEN_ALT, DTMF_OPEN_STD, SIP_TLS_PORT
from .const import DATA_DEVICES, DATA_OWN_PARAMS, DATA_SIP_PARAMS, DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up button entities from the stored device list."""
    data = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        BticinoButton(data[DATA_OWN_PARAMS], data[DATA_SIP_PARAMS], device, entry.entry_id)
        for device in data[DATA_DEVICES]
    )


class BticinoButton(ButtonEntity):
    """A button that sends door-activation OWN frames via SIP MESSAGE."""

    _attr_has_entity_name = True

    def __init__(
        self,
        own_params: dict,
        sip_params: dict,
        device: dict,
        entry_id: str,
    ) -> None:
        self._own_params = own_params
        self._sip_params = sip_params
        self._device = device

        cid = device["cid"]
        addr = device["addr"]
        dev = device.get("dev", "2")
        where = f"{dev}{addr}"
        self._attr_unique_id = f"{entry_id}_{cid}_{addr}"
        self._attr_name = device.get("name", f"Attivazione {cid}")

        if cid in CID_STANDARD:
            self._frame_open = f"{DTMF_OPEN_STD}*{where}##"
            self._frame_close = f"{DTMF_CLOSE_STD}*{where}##"
        else:
            self._frame_open = f"{DTMF_OPEN_ALT}*{where}##"
            self._frame_close = f"{DTMF_CLOSE_ALT}*{where}##"

        _LOGGER.debug(
            "Button '%s' configured: open=%s close=%s (dev=%r addr=%r)",
            self._attr_name, self._frame_open, self._frame_close, dev, addr,
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
        """Send open + close OWN frames to the gateway via SIP MESSAGE."""
        sip_username = self._sip_params.get("sip_username", "")
        sip_password = self._sip_params.get("sip_password", "")
        sip_domain = self._sip_params.get("sip_domain", "")
        local_ip = self._sip_params.get("local_ip", "")

        if not sip_username or not sip_domain:
            _LOGGER.error(
                "Button '%s' — SIP credentials not configured. "
                "Delete and re-add the integration to fetch them.",
                self._attr_name,
            )
            return

        creds = SipCredentials(
            username=sip_username,
            password=sip_password,
            domain=sip_domain,
        )
        target = f"sip:c300x@{sip_domain}"

        _LOGGER.info(
            "Button '%s' pressed — SIP %s → %s then %s",
            self._attr_name, target, self._frame_open, self._frame_close,
        )

        try:
            async with BticinoSipClient(
                credentials=creds,
                local_ip=local_ip or None,
                sip_port=SIP_TLS_PORT,
            ) as client:
                await client.send_message(target, self._frame_open)
                await asyncio.sleep(0.3)
                await client.send_message(target, self._frame_close)

            _LOGGER.info("Button '%s' — SIP sequence completed successfully", self._attr_name)

        except BticinoSipError as exc:
            _LOGGER.error(
                "Button '%s' — SIP error: %s",
                self._attr_name, exc,
            )
            raise
