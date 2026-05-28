"""Button entities for Bticino C300X — door activation via SIP MESSAGE (TLS 5061)."""

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
from .bticino_lib.models import SipCredentials, TlsCertificates
from .bticino_lib.const import (
    CID_STANDARD,
    DTMF_CLOSE_ALT,
    DTMF_CLOSE_STD,
    DTMF_OPEN_ALT,
    DTMF_OPEN_STD,
    SIP_TLS_PORT,
)
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
    """A button that opens a door via SIP MESSAGE to the local gateway (TLS 5061)."""

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

        cid  = device["cid"]
        addr = device["addr"]        # parte addr (p_default/address o ist.where)
        dev  = device.get("dev", "") # parte dev  (p_default/dev o obj.dev)
        # WHERE = dev + addr — identico a VctDoorLockTrigger.a() nell'app ufficiale
        where = f"{dev}{addr}" if dev else addr

        self._attr_unique_id = f"{entry_id}_{cid}_{addr}"
        self._attr_name = device.get("name", f"Attivazione {cid}")

        if cid in CID_STANDARD:
            self._frame_open  = f"{DTMF_OPEN_STD}*{where}##"
            self._frame_close = f"{DTMF_CLOSE_STD}*{where}##"
        else:
            self._frame_open  = f"{DTMF_OPEN_ALT}*{where}##"
            self._frame_close = f"{DTMF_CLOSE_ALT}*{where}##"

        _LOGGER.debug(
            "Button '%s' configured: open=%s close=%s (dev=%r addr=%r where=%r)",
            self._attr_name, self._frame_open, self._frame_close, dev, addr, where,
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
        """Send open + close SIP MESSAGE to the local gateway via TLS 5061."""
        sip_username = self._sip_params.get("sip_username", "")
        sip_password = self._sip_params.get("sip_password", "")
        sip_domain   = self._sip_params.get("sip_domain", "")
        local_ip     = self._sip_params.get("local_ip", "")

        if not sip_username or not sip_domain:
            _LOGGER.error(
                "Button '%s' — credenziali SIP non configurate, "
                "elimina e riconfigura l'integrazione.",
                self._attr_name,
            )
            return

        if not local_ip:
            _LOGGER.error(
                "Button '%s' — local_ip non configurato.",
                self._attr_name,
            )
            return

        creds = SipCredentials(
            username=sip_username,
            password=sip_password,
            domain=sip_domain,
        )
        tls = TlsCertificates(
            ca_cert_pem=self._sip_params.get("tls_ca_cert", ""),
            client_cert_pem=self._sip_params.get("tls_client_cert", ""),
            client_key_pem=self._sip_params.get("tls_client_key", ""),
        )
        target = f"sip:c300x@{sip_domain}"

        _LOGGER.debug(
            "Button '%s' — SIP params: username=%r domain=%r local_ip=%r "
            "ca_cert=%s client_cert=%s client_key=%s",
            self._attr_name,
            sip_username,
            sip_domain,
            local_ip,
            bool(tls.ca_cert_pem),
            bool(tls.client_cert_pem),
            bool(tls.client_key_pem),
        )
        _LOGGER.info(
            "Button '%s' — SIP TLS %s:%s → %s then %s (client_cert: %s)",
            self._attr_name, local_ip, SIP_TLS_PORT,
            self._frame_open, self._frame_close,
            bool(tls.client_cert_pem),
        )

        try:
            async with BticinoSipClient(
                credentials=creds,
                tls=tls,
                local_ip=local_ip,
                sip_port=SIP_TLS_PORT,
                use_tls=True,
            ) as client:
                await client.send_message(target, self._frame_open)
                await asyncio.sleep(0.3)
                await client.send_message(target, self._frame_close)

            _LOGGER.info("Button '%s' — SIP sequenza completata", self._attr_name)

        except BticinoSipError as exc:
            _LOGGER.error("Button '%s' — SIP error: %s", self._attr_name, exc)
            raise
