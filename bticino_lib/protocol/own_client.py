"""OWN local protocol client for Bticino C300X (TCP port 20000).

Connects directly to the gateway on the LAN — no cloud, no SIP.
The gateway uses BTicino Open Web Net text protocol:

  Frame format:  *WHO*WHAT*WHERE##
  ACK:           *#*1##
  NACK:          *#*0##

Authentication (if required) uses SHA-256 challenge-response,
reverse-engineered from f0.C0816a in the decompiled app.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import uuid

from ..const import OWN_DEFAULT_PORT, OWN_ACK, OWN_NACK
from ..exceptions import BticinoOwnError

_LOGGER = logging.getLogger(__name__)

_OWN_MAGIC = "736F70653E636F70653E"   # "sope>cope>" — from C0816a


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _nybbles(hex_str: str) -> str:
    result = []
    for ch in hex_str:
        n = str(int(ch, 16))
        if len(n) == 1:
            result.append("0")
        result.append(n)
    return "".join(result)


def _hex_encode_mac(mac: str) -> str:
    result = []
    i = 0
    while i < len(mac):
        chunk = mac[i : i + 2]
        try:
            result.append(hex(int(chunk, 16))[2:])
        except ValueError:
            result.append(chunk)
        i += 2
    return "".join(result)


class _OwnAuth:
    """SHA-256 challenge-response for OWN auth version 2 (from f0.C0816a)."""

    def __init__(self, server_mac: str, password: str) -> None:
        mac_hex = _hex_encode_mac(server_mac.replace(":", "").replace("-", ""))
        pwd_hash = _sha256_hex(password)
        nonce_hash = _sha256_hex(str(uuid.uuid4()))
        self._nonce_nibbles = _nybbles(nonce_hash)
        combined = mac_hex + nonce_hash + _OWN_MAGIC + pwd_hash
        self._client_token = _nybbles(_sha256_hex(combined))
        self._verify_input = mac_hex + nonce_hash + pwd_hash

    @property
    def nonce(self) -> str:
        return self._nonce_nibbles

    @property
    def client_token(self) -> str:
        return self._client_token

    def verify_server(self, server_token: str) -> bool:
        return server_token == _nybbles(_sha256_hex(self._verify_input))


class BticinoOwnClient:
    """Async OWN local protocol client.

    Usage::

        async with BticinoOwnClient("192.168.1.50", "689792705") as client:
            await client.send_raw("*8*19*0##")
            await asyncio.sleep(0.3)
            await client.send_raw("*8*20*0##")
    """

    def __init__(
        self,
        host: str,
        password: str = "12345",
        port: int = OWN_DEFAULT_PORT,
        timeout: float = 10.0,
    ) -> None:
        self._host = host
        self._password = password
        self._port = port
        self._timeout = timeout
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def __aenter__(self) -> "BticinoOwnClient":
        await self.connect()
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    async def connect(self) -> None:
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError as exc:
            raise BticinoOwnError(f"Timeout connecting to {self._host}:{self._port}") from exc
        except OSError as exc:
            raise BticinoOwnError(f"Cannot connect to {self._host}:{self._port}: {exc}") from exc
        await self._handshake()

    async def close(self) -> None:
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        self._reader = None
        self._writer = None

    async def send_raw(self, frame: str) -> str:
        """Send an OWN frame and return the gateway response."""
        response = await self._send_raw_frame(frame)
        _LOGGER.debug("OWN cmd %s -> %s", frame, response)
        if response == OWN_NACK:
            raise BticinoOwnError(f"Gateway NACK for command: {frame}")
        return response

    async def _handshake(self) -> None:
        welcome = await self._read_frame()
        _LOGGER.debug("OWN welcome: %s", welcome)
        if welcome == OWN_ACK:
            return
        if welcome == OWN_NACK:
            raise BticinoOwnError("Gateway refused connection (*#*0##)")
        if "*98*" in welcome or "*99*" in welcome:
            await self._authenticate(welcome)
            return
        _LOGGER.debug("OWN: unexpected welcome %s — assuming no auth", welcome)

    async def _authenticate(self, challenge: str) -> None:
        digits_match = (
            re.search(r"\*(\d+)\*\*#", challenge)
            or re.search(r"\*98\*#\*#\*(\w+)##", challenge)
        )
        if not digits_match:
            response = f"*#*{self._password}##" if self._password else OWN_ACK
            resp = await self._send_raw_frame(response)
            if resp == OWN_ACK:
                return
            raise BticinoOwnError(f"OWN simple auth failed: {resp}")

        mac_match = re.search(r"MAC[^#]*?([0-9A-Fa-f]{12})", challenge)
        server_mac = mac_match.group(1) if mac_match else "000000000000"
        auth = _OwnAuth(server_mac, self._password)
        resp = await self._send_raw_frame(f"*#*{auth.client_token}*{auth.nonce}##")
        if resp == OWN_ACK:
            return
        if resp and resp not in (OWN_NACK, OWN_ACK):
            token_match = re.search(r"\*#\*(\w+)", resp)
            if token_match and auth.verify_server(token_match.group(1)):
                return
        raise BticinoOwnError(f"OWN HMAC auth failed: {resp}")

    async def _send_raw_frame(self, frame: str) -> str:
        if not self._writer or not self._reader:
            raise BticinoOwnError("Not connected")
        _LOGGER.debug("OWN >>> %s", frame)
        self._writer.write(frame.encode())
        await self._writer.drain()
        return await self._read_frame()

    async def _read_frame(self) -> str:
        if not self._reader:
            raise BticinoOwnError("Not connected")
        buf = b""
        try:
            while b"##" not in buf:
                chunk = await asyncio.wait_for(
                    self._reader.read(256), timeout=self._timeout
                )
                if not chunk:
                    raise BticinoOwnError("Connection closed by gateway")
                buf += chunk
        except asyncio.TimeoutError as exc:
            raise BticinoOwnError("Timeout waiting for OWN response") from exc
        frame = buf.split(b"##")[0].decode("utf-8", errors="replace") + "##"
        _LOGGER.debug("OWN <<< %s", frame)
        return frame
