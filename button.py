"""Button entities for Bticino C300X — door activation via SIP MESSAGE local."""

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

SIP_LOCAL_PORT = 5060   # plain TCP, no TLS — gateway espone SIP in chiaro sulla LAN


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
    """A button that opens a door via SIP MESSAGE to the local gateway.

    Transport order:
      1. SIP local plain TCP 5060  — no TLS, works su LAN con Python 3.14
      2. SIP local TLS 5061        — fallback se il gateway richiede TLS locale
    """

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
        addr = device["addr"]           # parte addr (da XML: p_default/address o ist.where)
        dev  = device.get("dev", "")    # parte dev  (da XML: p_default/dev o obj.dev)
        # WHERE = dev + addr (identico a come l'app ufficiale costruisce il frame SIP)
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
        """Send open + close SIP MESSAGE to the local gateway."""
        sip_username = self._sip_params.get("sip_username", "")
        sip_password = self._sip_params.get("sip_password", "")
        sip_domain   = self._sip_params.get("sip_domain", "")
        local_ip     = self._sip_params.get("local_ip", "")

        if not sip_username or not sip_domain:
            _LOGGER.error(
                "Button '%s' — credenziali SIP non configurate, elimina e riconfigura l'integrazione.",
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

        # Tenta prima SIP plain TCP sulla LAN, poi TLS come fallback
        if local_ip:
            try:
                await self._send_sip(
                    creds, tls, target,
                    host=local_ip, port=SIP_LOCAL_PORT, use_tls=False,
                )
                return
            except BticinoSipError as exc:
                _LOGGER.warning(
                    "Button '%s' — SIP locale plain 5060 fallito (%s), provo TLS 5061",
                    self._attr_name, exc,
                )
            try:
                await self._send_sip(
                    creds, tls, target,
                    host=local_ip, port=SIP_TLS_PORT, use_tls=True,
                )
                return
            except BticinoSipError as exc:
                _LOGGER.error(
                    "Button '%s' — SIP locale TLS 5061 fallito: %s",
                    self._attr_name, exc,
                )
                raise
        else:
            _LOGGER.error(
                "Button '%s' — local_ip non configurato, impossibile raggiungere il gateway.",
                self._attr_name,
            )

    async def _send_sip(
        self,
        creds: SipCredentials,
        tls: TlsCertificates,
        target: str,
        host: str,
        port: int,
        use_tls: bool,
    ) -> None:
        proto = "TLS" if use_tls else "TCP"
        _LOGGER.info(
            "Button '%s' — SIP %s %s:%s → %s then %s",
            self._attr_name, proto, host, port,
            self._frame_open, self._frame_close,
        )
        async with BticinoSipClient(
            credentials=creds,
            tls=tls if use_tls else None,
            local_ip=host,
            sip_port=port,
            use_tls=use_tls,
        ) as client:
            await client.send_message(target, self._frame_open)
            await asyncio.sleep(0.3)
            await client.send_message(target, self._frame_close)

        _LOGGER.info("Button '%s' — SIP %s sequenza completata", self._attr_name, proto)
