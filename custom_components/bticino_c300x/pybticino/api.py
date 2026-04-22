"""REST API client for the Bticino cloud portal."""

from __future__ import annotations

import base64
import io
import json as _json
import logging
import re
import zipfile
from typing import Optional
from xml.etree import ElementTree as ET

import aiohttp

try:
    import pyzipper as _ziplib
    _USE_PYZIPPER = True
except ImportError:
    _ziplib = zipfile  # type: ignore[assignment]
    _USE_PYZIPPER = False


def _open_zip(data: bytes):
    if _USE_PYZIPPER:
        return _ziplib.AESZipFile(io.BytesIO(data))
    return zipfile.ZipFile(io.BytesIO(data))


from .auth import BticinoAuth
from .const import (
    API_GW_CONF,
    API_GW_INFO,
    API_GW_LIST,
    API_PLANTS,
    API_SIP_USER,
    API_TLS,
    CONF_ZIP_PASSWORD,
    HEADER_MAC_ADDRESS,
    HEADER_NEED_TOKEN,
    PORTAL_BASE_URL,
)
from .exceptions import BticinoApiError
from .models import DeviceInfo, GatewayInfo, PlantInfo, SipCredentials, TlsCertificates

_LOGGER = logging.getLogger(__name__)


class BticinoApiClient:
    """High-level REST client.

    Wraps BticinoAuth and adds domain-specific calls for plants,
    gateways, SIP credentials and TLS certificates.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        base_url: str = PORTAL_BASE_URL,
    ) -> None:
        self._auth = BticinoAuth(session, base_url)
        self._base_url = base_url.rstrip("/")

    # ------------------------------------------------------------------
    # Auth shortcuts
    # ------------------------------------------------------------------

    async def login(self, username: str, password: str) -> None:
        await self._auth.login(username, password)

    @property
    def token(self) -> Optional[str]:
        return self._auth.token

    # ------------------------------------------------------------------
    # Plants & Gateways
    # ------------------------------------------------------------------

    async def get_plants(self) -> list[PlantInfo]:
        """Return all plants (installations) associated with the account."""
        data = await self._auth._request("GET", API_PLANTS)

        plants: list[PlantInfo] = []
        items = data if isinstance(data, list) else data.get("plants", [])
        for item in items:
            plant_id = str(
                item.get("PlantId") or item.get("id") or item.get("plant_id", "")
            )
            name = item.get("PlantName") or item.get("name", plant_id)
            plants.append(PlantInfo(plant_id=plant_id, name=name))

        _LOGGER.debug("Found %d plant(s)", len(plants))
        return plants

    async def get_gateways(self, plant_id: str) -> list[GatewayInfo]:
        """Return all gateways for a plant."""
        data: list | dict = {}
        for path in (
            f"/eliot/plants/{plant_id}/gateways",
            API_GW_LIST.format(plant_id=plant_id),
        ):
            try:
                data = await self._auth._request("GET", path)
            except BticinoApiError:
                continue
            # considera valido solo se ha contenuto utile
            items_probe = data if isinstance(data, list) else (data or {}).get("gateways") or []
            if items_probe:
                break

        gateways: list[GatewayInfo] = []
        items = data if isinstance(data, list) else (data or {}).get("gateways", [data] if data else [])
        for item in items:
            if not isinstance(item, dict):
                continue
            gw_id = str(
                item.get("GatewayId") or item.get("id") or
                item.get("gatewayId") or item.get("gw_id", "")
            )
            mac = str(item.get("mac") or item.get("macAddress") or item.get("MacAddress") or "")
            own_password = str(item.get("PswOpen") or "")
            if not gw_id:
                continue
            gw = GatewayInfo(gateway_id=gw_id, mac_address=mac, plant_id=plant_id)
            gateways.append(gw)
            if own_password:
                _LOGGER.debug("PswOpen found in gateway list for %s: %s", gw_id, own_password)

        _LOGGER.debug("Found %d gateway(s) for plant %s", len(gateways), plant_id)
        return gateways

    # ------------------------------------------------------------------
    # SIP credentials
    # ------------------------------------------------------------------

    async def get_sip_credentials(
        self, plant_id: str, gateway_id: str, device_mac: str
    ) -> SipCredentials:
        """Fetch SIP username + password for a gateway.

        Endpoint: GET /eliot/sip/users/plants/{plant_id}/gateway/{gw_id}
        The device MAC (wifi MAC uppercase, no colons) is sent as a query
        parameter to identify the client device.
        """
        path = API_SIP_USER.format(plant_id=plant_id, gw_id=gateway_id)
        data = await self._auth._request(
            "GET", path, params={"deviceId": device_mac}
        )

        # Il server ritorna una lista di tutti i device registrati
        if isinstance(data, list):
            item = data[0] if data else {}
        else:
            item = data

        try:
            username = (
                item.get("SipAccount") or item.get("sipAccount") or item["SipAccount"]
            )
            password = (
                item.get("SipPassword") or item.get("sipPassword") or item["SipPassword"]
            )
            domain = item.get("domain") or f"{gateway_id}.bs.iotleg.com"
            device_name = item.get("DeviceName") or item.get("deviceName", "")
        except KeyError as exc:
            raise BticinoApiError(f"Unexpected SIP user response: {item}") from exc

        _LOGGER.debug("SIP credentials acquired for gateway %s", gateway_id)
        return SipCredentials(
            username=username,
            password=password,
            domain=domain,
            gateway_id=gateway_id,
            device_name=device_name,
        )

    # ------------------------------------------------------------------
    # TLS certificates
    # ------------------------------------------------------------------

    async def get_tls_certificates(self, device_id: str) -> TlsCertificates:
        """Fetch the TLS client certificates for mutual auth with the SIP server.

        Endpoint: GET /eliot/sip/tls/{device_id}
        Returns Base64-encoded PEM certs; we decode them here.
        """
        path = API_TLS.format(device_id=device_id)
        data = await self._auth._request("GET", path)

        def _decode(key: str) -> str:
            raw = data.get(key, "")
            if not raw:
                return ""
            try:
                return base64.b64decode(raw).decode("utf-8")
            except Exception:
                return raw  # already PEM or unknown format

        ca = _decode("caCert") or _decode("ca_cert") or _decode("rootCa")
        cert = _decode("clientCert") or _decode("client_cert")
        key = _decode("clientKey") or _decode("client_key")

        _LOGGER.debug("TLS certificates acquired for device %s", device_id)
        return TlsCertificates(
            ca_cert_pem=ca,
            client_cert_pem=cert,
            client_key_pem=key,
        )

    # ------------------------------------------------------------------
    # Convenience: fetch everything needed for local operation
    # ------------------------------------------------------------------

    async def fetch_gateway_config(
        self,
        plant_id: str,
        gateway_id: str,
        device_mac: str,
    ) -> tuple[SipCredentials, TlsCertificates]:
        """Return SIP credentials + TLS certs in a single call."""
        sip_creds, tls_certs = await _gather(
            self.get_sip_credentials(plant_id, gateway_id, device_mac),
            self.get_tls_certificates(device_mac),
        )
        return sip_creds, tls_certs


    # ------------------------------------------------------------------
    # Gateway extended info (includes OWN password)
    # ------------------------------------------------------------------

    async def get_gateway_info(
        self, plant_id: str, gateway_id: str, device_mac: str
    ) -> dict:
        """Fetch gateway info including the OWN local password (PswOpen).

        Endpoint: GET /eliot/plants/{plant_id}/gateway/{gw_id}
        The device MAC (wifi MAC uppercase, no colons) is sent as a header.

        Returns a dict with at least:
          - PswOpen  : password for OWN local protocol
          - GatewayId: gateway identifier
          - MacAddress: gateway MAC
          - Token    : temporary token
        """
        path = API_GW_INFO.format(plant_id=plant_id, gw_id=gateway_id)
        data = await self._auth._request(
            "GET",
            path,
            extra_headers={
                HEADER_NEED_TOKEN: "1",
                HEADER_MAC_ADDRESS: device_mac,
            },
        )

        # Il server ritorna direttamente {MacAddress, PswOpen, Token} senza wrapper payload
        if isinstance(data, dict) and "payload" in data:
            payload_str = data.get("payload", "{}")
            try:
                data = _json.loads(payload_str)
            except _json.JSONDecodeError as exc:
                raise BticinoApiError(f"Cannot parse gateway info payload: {exc}") from exc

        _LOGGER.debug(
            "Gateway info acquired for %s (PswOpen present: %s)",
            gateway_id,
            bool(data.get("PswOpen")),
        )
        return data

    # ------------------------------------------------------------------
    # Plant device configuration (activations)
    # ------------------------------------------------------------------

    async def get_plant_config(
        self, plant_id: str, gateway_id: str
    ) -> list[DeviceInfo]:
        """Fetch and parse the plant configuration ZIP to get the device list."""
        devices, _ = await self.get_plant_setup(plant_id, gateway_id)
        return devices

    async def get_plant_setup(
        self, plant_id: str, gateway_id: str
    ) -> tuple[list[DeviceInfo], str]:
        """Fetch conf ZIP and return (devices, local_wifi_ip).

        Parses conf.xml (VDE door = Serratura) + archive.xml (user activations)
        + read-only-par.txt (gateway WiFi IP).
        """
        path = API_GW_CONF.format(plant_id=plant_id, gw_id=gateway_id)
        payload_b64 = await self._auth._request_raw("GET", path)
        if not payload_b64 or not payload_b64.strip():
            raise BticinoApiError("Empty payload in /conf response")

        try:
            zip_bytes = base64.b64decode(payload_b64.strip())
        except Exception as exc:
            raise BticinoApiError(f"Cannot base64-decode /conf payload: {exc}") from exc

        try:
            with _open_zip(zip_bytes) as zf:
                zf.setpassword(CONF_ZIP_PASSWORD)
                names = zf.namelist()
                conf_xml = re.sub(
                    r"^.*?(<\?xml|<configuratore)", r"\1",
                    zf.read("conf.xml").decode("utf-8", errors="replace"),
                    flags=re.DOTALL,
                )
                archive_xml = (
                    zf.read("archive.xml").decode("utf-8", errors="replace")
                    if "archive.xml" in names else "<archive/>"
                )
                readonly_txt = (
                    zf.read("read-only-par.txt").decode("utf-8", errors="replace")
                    if "read-only-par.txt" in names else ""
                )
        except Exception as exc:
            raise BticinoApiError(f"Cannot read /conf ZIP: {exc}") from exc

        devices = _parse_all_devices(conf_xml, archive_xml)
        local_ip = _extract_wifi_ip(readonly_txt)

        _LOGGER.debug(
            "Plant setup parsed for gateway %s: %d device(s), local_ip=%s",
            gateway_id, len(devices), local_ip or "(unknown)",
        )
        return devices, local_ip


async def _gather(*coros):
    import asyncio
    return await asyncio.gather(*coros)


def _extract_wifi_ip(readonly_txt: str) -> str:
    """Extract WiFi IP from read-only-par.txt (JSON: {"wifi": {"ip": "..."}})."""
    try:
        import json
        return json.loads(readonly_txt).get("wifi", {}).get("ip", "") or ""
    except Exception:
        return ""


def _parse_all_devices(conf_xml: str, archive_xml: str) -> list[DeviceInfo]:
    """Parse conf.xml + archive.xml and return the full activation device list.

    - conf.xml  → one "Serratura" entry (VDE door, CID 10060, addr = p_default)
    - archive.xml → user activations (type="1", non-camera objects)
    """
    # --- conf.xml: extract p_default address (Serratura) ---
    P, p_dev = 0, "2"
    try:
        root = ET.fromstring(conf_xml)
        comm = root.find("./setup/vdes/communication")
        if comm is not None:
            p_addr_el = comm.find("p_default/address")
            p_dev_el = comm.find("p_default/dev")
            if p_addr_el is not None and p_addr_el.text:
                P = int(p_addr_el.text)
            if p_dev_el is not None and p_dev_el.text:
                p_dev = p_dev_el.text
    except ET.ParseError:
        _LOGGER.warning("conf.xml parse error, using defaults P=%s dev=%s", P, p_dev)

    devices: list[DeviceInfo] = []
    devices.append(DeviceInfo(cid=10060, name="Serratura", addr=str(P), dev=p_dev))

    # --- archive.xml: user activations (skip cameras CID 10061) ---
    _SKIP_CIDS = {10061}
    try:
        root = ET.fromstring(archive_xml)
        for obj in root.findall("obj"):
            cid_str = obj.get("cid", "0")
            try:
                cid = int(cid_str)
            except ValueError:
                continue
            if cid in _SKIP_CIDS:
                continue
            dev = obj.get("dev", "2")
            for ist in obj.findall("ist"):
                if ist.get("type") != "1":
                    continue
                addr = ist.get("where", "0")
                name = ist.get("descr") or obj.get("descr") or f"Attivazione {cid}"
                devices.append(DeviceInfo(cid=cid, name=name, addr=addr, dev=dev))
    except ET.ParseError:
        _LOGGER.warning("archive.xml parse error, skipping user activations")

    return devices


def _parse_conf_devices(conf_xml: str, modality_str: str) -> list[DeviceInfo]:
    """Legacy parser kept for compatibility."""
    return _parse_all_devices(conf_xml, "<archive/>")

    # Device 2: CID 10060 (main intercom/citofono)
    devices.append(DeviceInfo(cid=10060, name="Citofono", addr=str(P), dev=dev))

    # Device 3: depends on M (modality)
    if M == 0:
        # Monofamiliare — uses CID 2009 and the N address
        devices.append(DeviceInfo(cid=2009, name="Pulsante monofamiliare", addr=str(N), dev="1"))
    elif M in (1, 2, 3):
        # Multifamiliare — extra citofono CID 10060 at P+M
        devices.append(DeviceInfo(cid=10060, name=f"Citofono {M}", addr=str(P + M), dev="2"))
    elif M in (4, 5, 6):
        # Multifamiliare — extra vivavoce CID 10050 at P+M-3
        devices.append(DeviceInfo(cid=10050, name=f"Vivavoce {M}", addr=str(P + M - 3), dev="2"))

    return devices
