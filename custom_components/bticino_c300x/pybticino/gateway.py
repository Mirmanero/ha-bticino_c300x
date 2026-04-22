"""High-level Bticino C300X gateway interface.

This is the main entry point for the Home Assistant integration.
It orchestrates auth, REST API, SIP and OWN clients to expose
simple, high-level methods like open_door().
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import aiohttp

from .api import BticinoApiClient
from .const import (
    CID_ALT,
    CID_STANDARD,
    DEFAULT_UNIT,
    DTMF_CLOSE_ALT,
    DTMF_CLOSE_STD,
    DTMF_OPEN_ALT,
    DTMF_OPEN_STD,
    OWN_DEFAULT_PORT,
    SIP_TLS_PORT,
)
from .exceptions import BticinoError, BticinoGatewayNotFound, BticinoSipError
from .models import DeviceInfo, GatewayConfig, GatewayInfo, PlantInfo, SipCredentials, TlsCertificates
from .own import BticinoOwnClient
from .sip import BticinoSipClient

_LOGGER = logging.getLogger(__name__)


class BticinoGateway:
    """Represents a single C300X gateway and exposes door control methods.

    Supports three transport modes (in preference order):
      1. OWN local  – TCP on LAN, no cloud (fastest, most reliable at home)
      2. SIP local  – SIP/TLS to gateway's local IP (requires SIP creds)
      3. SIP remote – SIP/TLS via Bticino cloud (works from anywhere)

    Typical setup::

        async with aiohttp.ClientSession() as session:
            gw = BticinoGateway.from_credentials(session, "user@email.com", "password")
            await gw.setup()                     # fetches creds from cloud (once)
            await gw.open_door()                 # opens the door
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        plant_info: PlantInfo,
        gateway_info: GatewayInfo,
        sip_credentials: Optional[SipCredentials] = None,
        tls_certificates: Optional[TlsCertificates] = None,
        device_mac: str = "",
        own_password: str = "12345",
    ) -> None:
        self._api = BticinoApiClient(session)
        self.plant = plant_info
        self.gateway = gateway_info
        self.sip_credentials = sip_credentials
        self.tls_certificates = tls_certificates
        self._device_mac = device_mac
        self._own_password = own_password
        self.devices: list[DeviceInfo] = []

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_config(
        cls,
        session: aiohttp.ClientSession,
        config: GatewayConfig,
        device_mac: str = "",
    ) -> "BticinoGateway":
        """Build a gateway from a previously fetched GatewayConfig."""
        return cls(
            session=session,
            plant_info=config.plant,
            gateway_info=config.gateway,
            sip_credentials=config.sip_credentials,
            tls_certificates=config.tls_certificates,
            device_mac=device_mac,
        )

    # ------------------------------------------------------------------
    # Cloud setup (call once, cache results)
    # ------------------------------------------------------------------

    async def cloud_login(self, username: str, password: str) -> None:
        """Authenticate against the Bticino cloud portal."""
        await self._api.login(username, password)
        _LOGGER.debug("Cloud login successful")

    async def fetch_credentials(self) -> None:
        """Download SIP credentials, TLS certs and OWN password from cloud.

        Must call cloud_login() first.  Results are stored on this instance.
        """
        plant_id = self.plant.plant_id
        gw_id = self.gateway.gateway_id
        mac = self._device_mac

        _LOGGER.debug("Fetching credentials for gateway %s", gw_id)
        self.sip_credentials, self.tls_certificates = (
            await self._api.fetch_gateway_config(plant_id, gw_id, mac)
        )

        if mac:
            try:
                gw_info = await self._api.get_gateway_info(plant_id, gw_id, mac)
                psw = gw_info.get("PswOpen", "")
                if psw:
                    self._own_password = psw
                    _LOGGER.debug("OWN password (PswOpen) acquired")
            except Exception as exc:
                _LOGGER.warning("Could not fetch PswOpen: %s", exc)

        _LOGGER.debug("Credentials fetched and stored")

    async def discover_devices(self) -> list[DeviceInfo]:
        """Download and parse the plant config to get the activations device list.

        Must call cloud_login() first.  Results are stored in self.devices.
        Returns the list of DeviceInfo objects (one per activatable device).
        """
        plant_id = self.plant.plant_id
        gw_id = self.gateway.gateway_id

        _LOGGER.debug("Fetching device list for gateway %s", gw_id)
        self.devices = await self._api.get_plant_config(plant_id, gw_id)
        _LOGGER.info(
            "Discovered %d device(s) for gateway %s", len(self.devices), gw_id
        )
        return self.devices

    # ------------------------------------------------------------------
    # Door control
    # ------------------------------------------------------------------

    async def open_door(
        self,
        cid: int = 10060,
        unit: str = DEFAULT_UNIT,
        prefer_local: bool = True,
    ) -> None:
        """Open the door.

        Args:
            cid:   Device CID (10060/3008 for standard VDE, 2009 for alternate).
            unit:  Unit identifier on the bus (default "4").
            prefer_local: Try OWN local first; fall back to SIP if it fails.
        """
        dtmf_open, dtmf_close = self._dtmf_for_cid(cid, unit)

        if prefer_local and self.gateway.local_ip:
            try:
                await self._open_via_own(dtmf_open, dtmf_close)
                return
            except BticinoError as exc:
                _LOGGER.warning(
                    "OWN local failed (%s), falling back to SIP", exc
                )

        await self._open_via_sip(dtmf_open, dtmf_close)

    async def open_door_local_only(
        self,
        cid: int = 10060,
        unit: str = DEFAULT_UNIT,
    ) -> None:
        """Open via OWN local protocol only (raises if no local IP)."""
        if not self.gateway.local_ip:
            raise BticinoGatewayNotFound(
                "No local IP set for gateway. Run local_discovery() first."
            )
        dtmf_open, dtmf_close = self._dtmf_for_cid(cid, unit)
        await self._open_via_own(dtmf_open, dtmf_close)

    async def open_door_remote(
        self,
        cid: int = 10060,
        unit: str = DEFAULT_UNIT,
    ) -> None:
        """Open via remote SIP (works outside home network)."""
        dtmf_open, dtmf_close = self._dtmf_for_cid(cid, unit)
        await self._open_via_sip(dtmf_open, dtmf_close, force_remote=True)

    # ------------------------------------------------------------------
    # Local gateway discovery
    # ------------------------------------------------------------------

    async def local_discovery(
        self,
        subnet_prefix: str,
        port: int = OWN_DEFAULT_PORT,
        max_concurrent: int = 20,
        timeout_per_host: float = 1.5,
    ) -> Optional[str]:
        """Scan the local subnet for the gateway and store its IP.

        Args:
            subnet_prefix: e.g. "192.168.1" (last octet is iterated 1-254)
            port:          OWN port to probe (default 12345)
            max_concurrent: parallel probes
            timeout_per_host: seconds before giving up on each host

        Returns the discovered IP or None.
        """
        _LOGGER.debug("Scanning subnet %s.x for gateway %s",
                      subnet_prefix, self.gateway.gateway_id)

        sem = asyncio.Semaphore(max_concurrent)

        async def probe(host: str) -> Optional[str]:
            async with sem:
                try:
                    _r, w = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=timeout_per_host,
                    )
                    w.close()
                    try:
                        await w.wait_closed()
                    except Exception:
                        pass
                    return host
                except Exception:
                    return None

        tasks = [
            asyncio.create_task(probe(f"{subnet_prefix}.{i}"))
            for i in range(1, 255)
        ]
        results = await asyncio.gather(*tasks)
        candidates = [ip for ip in results if ip]

        if not candidates:
            _LOGGER.warning("No hosts found on %s.x:%s", subnet_prefix, port)
            return None

        # If exactly one candidate, trust it
        if len(candidates) == 1:
            self.gateway.local_ip = candidates[0]
            _LOGGER.info("Gateway discovered at %s", self.gateway.local_ip)
            return self.gateway.local_ip

        # Multiple candidates: verify with OWN handshake (MAC matching)
        for ip in candidates:
            try:
                async with BticinoOwnClient(
                    ip, "", port=port, timeout=timeout_per_host
                ):
                    # if it doesn't raise during connect/handshake it's likely our gateway
                    self.gateway.local_ip = ip
                    _LOGGER.info("Gateway identified at %s", ip)
                    return ip
            except Exception:
                continue

        return None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _dtmf_for_cid(self, cid: int, unit: str) -> tuple[str, str]:
        if cid in CID_STANDARD:
            return f"{DTMF_OPEN_STD}*{unit}##", f"{DTMF_CLOSE_STD}*{unit}##"
        if cid in CID_ALT:
            return f"{DTMF_OPEN_ALT}*{unit}##", f"{DTMF_CLOSE_ALT}*{unit}##"
        _LOGGER.warning("Unknown CID %s, using standard commands", cid)
        return f"{DTMF_OPEN_STD}*{unit}##", f"{DTMF_CLOSE_STD}*{unit}##"

    async def _open_via_own(self, dtmf_open: str, dtmf_close: str) -> None:
        if not self.gateway.local_ip:
            raise BticinoGatewayNotFound("No local IP for OWN client")

        async with BticinoOwnClient(
            self.gateway.local_ip,
            self._own_password,
            port=self.gateway.own_port,
        ) as client:
            await client.send_raw(dtmf_open)
            await asyncio.sleep(0.3)
            await client.send_raw(dtmf_close)

    async def _open_via_sip(
        self,
        dtmf_open: str,
        dtmf_close: str,
        force_remote: bool = False,
    ) -> None:
        if not self.sip_credentials:
            raise BticinoSipError(
                "No SIP credentials. Call fetch_credentials() first."
            )

        local_ip = None if force_remote else self.gateway.local_ip
        target = (
            f"sip:c300x@{self.sip_credentials.domain}"
        )

        async with BticinoSipClient(
            credentials=self.sip_credentials,
            tls=self.tls_certificates,
            local_ip=local_ip,
            sip_port=SIP_TLS_PORT,
        ) as client:
            await client.send_message(target, dtmf_open)
            await asyncio.sleep(0.3)
            await client.send_message(target, dtmf_close)
