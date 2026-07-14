"""Bticino C300X Home Assistant integration.

Works local-only via OWN protocol after initial cloud setup.
"""

from __future__ import annotations

import asyncio
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .bticino_lib import BticinoSipListener
from .bticino_lib.models import SipCredentials, TlsCertificates
from .const import (
    CONF_DEVICES,
    CONF_GATEWAY_ID,
    CONF_LOCAL_IP,
    CONF_OWN_PASSWORD,
    CONF_SIP_DOMAIN,
    CONF_SIP_PASSWORD,
    CONF_SIP_USERNAME,
    CONF_TLS_CA_CERT,
    CONF_TLS_CLIENT_CERT,
    CONF_TLS_CLIENT_KEY,
    DATA_DEVICES,
    DATA_DOORBELL_LISTENER,
    DATA_OWN_PARAMS,
    DATA_SIP_PARAMS,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["button", "binary_sensor"]

_LISTENER_TASK_KEY = "doorbell_task"


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Bticino C300X from a config entry (no cloud calls at runtime)."""
    hass.data.setdefault(DOMAIN, {})

    hass.data[DOMAIN][entry.entry_id] = {
        DATA_OWN_PARAMS: {
            "local_ip": entry.data[CONF_LOCAL_IP],
            "own_password": entry.data[CONF_OWN_PASSWORD],
            "gateway_id": entry.data[CONF_GATEWAY_ID],
        },
        DATA_SIP_PARAMS: {
            "sip_username": entry.data.get(CONF_SIP_USERNAME, ""),
            "sip_password": entry.data.get(CONF_SIP_PASSWORD, ""),
            "sip_domain": entry.data.get(CONF_SIP_DOMAIN, ""),
            "local_ip": entry.data[CONF_LOCAL_IP],
            "tls_ca_cert": entry.data.get(CONF_TLS_CA_CERT, ""),
            "tls_client_cert": entry.data.get(CONF_TLS_CLIENT_CERT, ""),
            "tls_client_key": entry.data.get(CONF_TLS_CLIENT_KEY, ""),
        },
        DATA_DEVICES: entry.data.get(CONF_DEVICES, []),
    }

    d = hass.data[DOMAIN][entry.entry_id]
    sip = d[DATA_SIP_PARAMS]
    _LOGGER.debug(
        "Config entry loaded — gateway_id=%s local_ip=%s sip_username=%s sip_domain=%s "
        "tls_ca_cert=%s tls_client_cert=%s tls_client_key=%s devices=%d",
        entry.data.get(CONF_GATEWAY_ID),
        entry.data.get(CONF_LOCAL_IP),
        sip.get("sip_username"),
        sip.get("sip_domain"),
        bool(sip.get("tls_ca_cert")),
        bool(sip.get("tls_client_cert")),
        bool(sip.get("tls_client_key")),
        len(d[DATA_DEVICES]),
    )

    # Start SIP listener for doorbell detection if SIP is configured
    listener = None
    if sip.get("sip_username") and sip.get("sip_domain"):
        creds = SipCredentials(
            username=sip["sip_username"],
            password=sip["sip_password"],
            domain=sip["sip_domain"],
        )
        tls = TlsCertificates(
            ca_cert_pem=sip.get("tls_ca_cert", ""),
            client_cert_pem=sip.get("tls_client_cert", ""),
            client_key_pem=sip.get("tls_client_key", ""),
        )
        listener = BticinoSipListener(
            credentials=creds,
            tls=tls,
            local_ip=sip.get("local_ip", ""),
            on_invite=lambda: None,  # replaced by binary_sensor after platform setup
        )
        task = hass.async_create_background_task(
            listener.start(),
            name=f"bticino_sip_listener_{entry.entry_id}",
        )
        d[_LISTENER_TASK_KEY] = task
    else:
        _LOGGER.warning("Bticino: SIP not configured — doorbell detection disabled")

    d[DATA_DOORBELL_LISTENER] = listener

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    d = hass.data[DOMAIN].get(entry.entry_id, {})

    listener: BticinoSipListener | None = d.get(DATA_DOORBELL_LISTENER)
    if listener is not None:
        listener.stop()

    task: asyncio.Task | None = d.get(_LISTENER_TASK_KEY)
    if task is not None and not task.done():
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok
