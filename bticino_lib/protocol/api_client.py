"""Cloud REST client for the Bticino portal (myhomeweb.com).

Used only during the config flow to discover plant/gateway/devices/IP.
At runtime the integration operates locally via OWN protocol.
"""

from __future__ import annotations

import base64
import json as _json
import logging
import re
import zipfile
import io
from typing import Optional
from xml.etree import ElementTree as ET

import aiohttp

from ..const import (
    API_GW_CONF,
    API_GW_INFO,
    API_GW_LIST,
    API_PLANTS,
    API_SIGN_IN,
    API_SIP_USER,
    APP_VERSION,
    CONF_ZIP_PASSWORD,
    HEADER_AUTH_TOKEN,
    HEADER_MAC_ADDRESS,
    HEADER_NEED_TOKEN,
    HEADER_PRJ_NAME,
    PORTAL_BASE_URL,
)
from ..exceptions import BticinoApiError, BticinoAuthError, BticinoConnectionError
from ..models import DeviceInfo, GatewayInfo, PlantInfo, SipCredentials

_LOGGER = logging.getLogger(__name__)


class BticinoApiClient:
    """High-level cloud API client.

    Call login() once, then use the discovery methods.
    All discovery results are returned as plain Python objects —
    store them in the config entry and never call this again at runtime.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        base_url: str = PORTAL_BASE_URL,
    ) -> None:
        self._session = session
        self._base_url = base_url.rstrip("/")
        self._token: Optional[str] = None

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    async def login(self, username: str, password: str) -> None:
        payload = {
            "username": username,
            "pwd": password,
            "appVersion": APP_VERSION,
        }
        data = await self._request("POST", API_SIGN_IN, json=payload, authenticated=False)
        token = data.get(HEADER_AUTH_TOKEN)
        if not token:
            raise BticinoAuthError("Login response did not contain auth_token")
        self._token = token
        _LOGGER.debug("Login successful")

    # ------------------------------------------------------------------
    # Plant / Gateway discovery
    # ------------------------------------------------------------------

    async def get_plants(self) -> list[PlantInfo]:
        data = await self._request("GET", API_PLANTS)
        items = data if isinstance(data, list) else data.get("plants", [])
        return [
            PlantInfo(
                plant_id=str(i.get("PlantId") or i.get("id") or i.get("plant_id", "")),
                name=str(i.get("PlantName") or i.get("name", "")),
            )
            for i in items
        ]

    async def get_gateways(self, plant_id: str) -> list[GatewayInfo]:
        data: list | dict = {}
        for path in (
            f"/eliot/plants/{plant_id}/gateways",
            API_GW_LIST.format(plant_id=plant_id),
        ):
            try:
                data = await self._request("GET", path)
            except BticinoApiError:
                continue
            items_probe = data if isinstance(data, list) else (data or {}).get("gateways") or []
            if items_probe:
                break

        items = data if isinstance(data, list) else (data or {}).get("gateways", [data] if data else [])
        gateways = []
        for item in items:
            if not isinstance(item, dict):
                continue
            gw_id = str(
                item.get("GatewayId") or item.get("id") or
                item.get("gatewayId") or item.get("gw_id", "")
            )
            if not gw_id:
                continue
            mac = str(item.get("MacAddress") or item.get("mac") or item.get("macAddress") or "")
            gateways.append(GatewayInfo(gateway_id=gw_id, mac_address=mac, plant_id=plant_id))
        return gateways

    async def get_gateway_info(self, plant_id: str, gateway_id: str) -> dict:
        """Fetch gateway info: PswOpen, MacAddress, Token."""
        path = API_GW_INFO.format(plant_id=plant_id, gw_id=gateway_id)
        data = await self._request(
            "GET", path,
            extra_headers={HEADER_NEED_TOKEN: "1", HEADER_MAC_ADDRESS: ""},
        )
        if isinstance(data, dict) and "payload" in data:
            try:
                data = _json.loads(data["payload"])
            except Exception:
                pass
        return data if isinstance(data, dict) else {}

    async def get_plant_setup(
        self, plant_id: str, gateway_id: str
    ) -> tuple[list[DeviceInfo], str]:
        """Download the config ZIP and return (devices, wifi_ip).

        Parses conf.xml (VDE door = Serratura) and archive.xml (user
        activations like gate openers), plus reads the WiFi IP from
        read-only-par.txt.
        """
        path = API_GW_CONF.format(plant_id=plant_id, gw_id=gateway_id)
        payload_b64 = await self._request_raw("GET", path)
        if not payload_b64 or not payload_b64.strip():
            raise BticinoApiError("Empty payload in /conf response")

        try:
            zip_bytes = base64.b64decode(payload_b64.strip())
        except Exception as exc:
            raise BticinoApiError(f"Cannot base64-decode /conf payload: {exc}") from exc

        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
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

        devices = _parse_devices(conf_xml, archive_xml)
        local_ip = _extract_wifi_ip(readonly_txt)
        _LOGGER.debug(
            "Plant setup: %d device(s), local_ip=%s", len(devices), local_ip or "(unknown)"
        )
        return devices, local_ip

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    async def _request_raw(self, method: str, path: str) -> str:
        url = f"{self._base_url}{path}"
        headers = {
            HEADER_PRJ_NAME: "C3X",
            "Content-Type": "application/json",
        }
        if self._token:
            headers[HEADER_AUTH_TOKEN] = self._token
        try:
            async with self._session.request(method, url, headers=headers, ssl=True) as resp:
                _LOGGER.debug("%s %s -> %s (raw)", method, url, resp.status)
                if resp.status >= 400:
                    text = await resp.text()
                    raise BticinoApiError(
                        f"API error {resp.status} on {method} {path}: {text}",
                        status_code=resp.status,
                    )
                return await resp.text()
        except aiohttp.ClientConnectionError as exc:
            raise BticinoConnectionError(f"Cannot connect to {self._base_url}") from exc

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict | None = None,
        params: dict | None = None,
        authenticated: bool = True,
        extra_headers: dict | None = None,
    ) -> dict | list:
        url = f"{self._base_url}{path}"
        headers = {HEADER_PRJ_NAME: "C3X", "Content-Type": "application/json"}
        if authenticated:
            if not self._token:
                raise BticinoAuthError("Not authenticated. Call login() first.")
            headers[HEADER_AUTH_TOKEN] = self._token
        if extra_headers:
            headers.update(extra_headers)
        try:
            async with self._session.request(
                method, url, headers=headers, json=json, params=params, ssl=True
            ) as resp:
                _LOGGER.debug("%s %s -> %s", method, url, resp.status)
                if resp.status == 401:
                    self._token = None
                    raise BticinoAuthError(f"Authentication error on {method} {path} (HTTP 401)")
                if resp.status >= 400:
                    text = await resp.text()
                    raise BticinoApiError(
                        f"API error {resp.status} on {method} {path}: {text}",
                        status_code=resp.status,
                    )
                text = await resp.text()
                try:
                    body = _json.loads(text) if text.strip() else {}
                except Exception:
                    body = {}
                if body is None:
                    body = {}
                # auth_token is returned in the response header, not the body
                if (
                    HEADER_AUTH_TOKEN in resp.headers
                    and isinstance(body, dict)
                    and not body.get(HEADER_AUTH_TOKEN)
                ):
                    body[HEADER_AUTH_TOKEN] = resp.headers[HEADER_AUTH_TOKEN]
                return body
        except aiohttp.ClientConnectionError as exc:
            raise BticinoConnectionError(f"Cannot connect to {self._base_url}") from exc


    async def get_sip_credentials(
        self, plant_id: str, gateway_id: str, device_id: str
    ) -> SipCredentials:
        """Fetch SIP username + password for door activation.

        device_id is sent as ?deviceId= query param. It can be a real device MAC
        or a synthetic ID (the server will provision a new SIP account if needed).
        """
        path = API_SIP_USER.format(plant_id=plant_id, gw_id=gateway_id)
        data = await self._request("GET", path, params={"deviceId": device_id})

        item: dict = {}
        if isinstance(data, list):
            item = data[0] if data else {}
        elif isinstance(data, dict):
            item = data

        try:
            username = (
                item.get("SipAccount") or item.get("sipAccount") or item["SipAccount"]
            )
            password = (
                item.get("SipPassword") or item.get("sipPassword") or item["SipPassword"]
            )
            domain = item.get("domain") or f"{gateway_id}.bs.iotleg.com"
        except KeyError as exc:
            raise BticinoApiError(f"Unexpected SIP user response: {item}") from exc

        _LOGGER.debug("SIP credentials acquired for gateway %s", gateway_id)
        return SipCredentials(username=username, password=password, domain=domain)

    # ------------------------------------------------------------------
# ZIP parsing helpers
# ------------------------------------------------------------------

def _extract_wifi_ip(readonly_txt: str) -> str:
    try:
        return _json.loads(readonly_txt).get("wifi", {}).get("ip", "") or ""
    except Exception:
        return ""


def _parse_devices(conf_xml: str, archive_xml: str) -> list[DeviceInfo]:
    """Parse conf.xml + archive.xml into a device list.

    conf.xml  → one "Serratura" (VDE door, CID 10060, addr = p_default address)
    archive.xml → user activations (ist type="1", non-camera objects)
    """
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

    devices: list[DeviceInfo] = [
        DeviceInfo(cid=10060, name="Serratura", addr=str(P), dev=p_dev)
    ]

    try:
        root = ET.fromstring(archive_xml)
        for obj in root.findall("obj"):
            try:
                cid = int(obj.get("cid", "0"))
            except ValueError:
                continue
            if cid == 10061:    # skip cameras
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
