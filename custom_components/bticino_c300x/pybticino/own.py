"""OWN (Open Web Net) local protocol client for Bticino C300X.

The gateway listens on port 20000 and speaks the standard BTicino
Open Web Net text protocol:

  Frame format:  *WHO*WHAT*WHERE##
  ACK:           *#*1##
  NACK:          *#*0##

The door-open commands sent by the app via SIP are already OWN frames:
  open:   *8*19*{unit}##    (CID 10060 / 3008)
  close:  *8*20*{unit}##

We just send them directly over TCP — no SIP, no cloud needed.

Authentication (if the gateway requires it) uses SHA-256
challenge-response, reverse-engineered from f0.C0816a in the app.
The password ("PswOpen") is obtained from the cloud API once and
can be cached permanently.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from typing import Optional

from .const import OWN_DEFAULT_PORT
from .exceptions import BticinoOwnError

_LOGGER = logging.getLogger(__name__)

OWN_ACK = "*#*1##"
OWN_NACK = "*#*0##"
OWN_TERMINATOR = "##"


# ---------------------------------------------------------------------------
# OWN HMAC-SHA256 authentication  (from f0.C0816a in the decompiled app)
# ---------------------------------------------------------------------------

def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _nybbles(hex_str: str) -> str:
    """Convert each hex digit to its decimal nibble (from C0816a.d())."""
    result = []
    for ch in hex_str:
        n = str(int(ch, 16))
        if len(n) == 1:
            result.append("0")
        result.append(n)
    return "".join(result)


def _hex_encode_mac(mac: str) -> str:
    """Encode MAC address pairs as hex (from C0816a.a())."""
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


_OWN_MAGIC = "736F70653E636F70653E"   # "sope>cope>" in hex — from C0816a


class _OwnAuth:
    """SHA-256 challenge-response for OWN auth version 2 (from f0.C0816a)."""

    def __init__(self, server_mac: str, password: str) -> None:
        mac_hex = _hex_encode_mac(server_mac.replace(":", "").replace("-", ""))
        pwd_hash = _sha256_hex(password)
        nonce_raw = str(uuid.uuid4())
        nonce_hash = _sha256_hex(nonce_raw)

        self._nonce_nibbles = _nybbles(nonce_hash)

        combined = mac_hex + nonce_hash + _OWN_MAGIC + pwd_hash
        client_hash = _sha256_hex(combined)
        self._client_token = _nybbles(client_hash)

        # for server verification
        self._verify_input = mac_hex + nonce_hash + pwd_hash

    @property
    def nonce(self) -> str:
        return self._nonce_nibbles

    @property
    def client_token(self) -> str:
        return self._client_token

    def verify_server(self, server_token: str) -> bool:
        expected = _nybbles(_sha256_hex(self._verify_input))
        ok = server_token == expected
        if not ok:
            _LOGGER.warning("OWN: server token mismatch — wrong password?")
        return ok


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class BticinoOwnClient:
    """Async OWN local protocol client (port 20000, text format).

    Connects directly to the gateway on the LAN — no cloud, no SIP.

    The gateway immediately sends *#*1## upon connection if no
    authentication is required, or sends a challenge frame if auth
    is needed.  Both cases are handled here.

    Usage::

        async with BticinoOwnClient("192.168.1.50") as client:
            await client.open_door()         # sends *8*19*4##
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

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._authenticated = False

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "BticinoOwnClient":
        await self.connect()
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Connect / close
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open the TCP connection and complete the OWN handshake."""
        _LOGGER.debug("OWN connecting to %s:%s", self._host, self._port)
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError as exc:
            raise BticinoOwnError(
                f"Timeout connecting to {self._host}:{self._port}"
            ) from exc
        except OSError as exc:
            raise BticinoOwnError(
                f"Cannot connect to {self._host}:{self._port}: {exc}"
            ) from exc

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
        self._authenticated = False

    # ------------------------------------------------------------------
    # Public commands
    # ------------------------------------------------------------------

    async def open_door(self, unit: str = "4", cid: int = 10060) -> None:
        """Send the door-open OWN command.

        The gateway expects two frames: open + release (same as the app).
        """
        if cid in {10060, 3008}:
            open_cmd = f"*8*19*{unit}##"
            close_cmd = f"*8*20*{unit}##"
        elif cid == 2009:
            open_cmd = f"*8*21*{unit}##"
            close_cmd = f"*8*22*{unit}##"
        else:
            _LOGGER.warning("Unknown CID %s, using standard commands", cid)
            open_cmd = f"*8*19*{unit}##"
            close_cmd = f"*8*20*{unit}##"

        await self._send_command(open_cmd)
        await asyncio.sleep(0.3)
        await self._send_command(close_cmd)
        _LOGGER.info("OWN door opened (unit=%s)", unit)

    async def send_raw(self, frame: str) -> str:
        """Send any raw OWN frame and return the gateway response."""
        return await self._send_command(frame)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _handshake(self) -> None:
        """Read the initial gateway message and authenticate if needed."""
        welcome = await self._read_frame()
        _LOGGER.debug("OWN welcome: %s", welcome)

        if welcome == OWN_ACK:
            # Gateway accepted with no auth required — common in local network
            self._authenticated = True
            _LOGGER.debug("OWN: no auth required, ready")
            return

        if welcome == OWN_NACK:
            raise BticinoOwnError("Gateway refused connection (*#*0##)")

        # Auth challenge: *98*#*#*{something}## or similar
        if "*98*" in welcome or "*99*" in welcome:
            await self._authenticate(welcome)
            return

        # Some gateways send a numeric challenge  *99*##  or  *98*0##
        _LOGGER.debug("OWN: unexpected welcome frame: %s — assuming no auth", welcome)
        self._authenticated = True

    async def _authenticate(self, challenge: str) -> None:
        """Handle OWN password authentication challenge."""
        _LOGGER.debug("OWN auth challenge: %s", challenge)

        # Extract nonce digits from challenge (format varies by firmware)
        import re
        digits_match = re.search(r"\*(\d+)\*\*#", challenge) or \
                       re.search(r"\*98\*#\*#\*(\w+)##", challenge)

        if not digits_match:
            # Simple password auth: gateway just expects *#password##
            response = f"*#*{self._password}##" if self._password else OWN_ACK
            resp = await self._send_raw_frame(response)
            if resp == OWN_ACK:
                self._authenticated = True
                return
            raise BticinoOwnError(f"OWN auth failed: {resp}")

        nonce = digits_match.group(1)

        # HMAC-SHA256 auth (version 2 — from f0.C0816a)
        # Extract server MAC from challenge if available
        mac_match = re.search(r"MAC[^#]*?([0-9A-Fa-f]{12})", challenge)
        server_mac = mac_match.group(1) if mac_match else "000000000000"

        auth = _OwnAuth(server_mac, self._password)
        response = f"*#*{auth.client_token}*{auth.nonce}##"

        resp = await self._send_raw_frame(response)
        if resp == OWN_ACK:
            self._authenticated = True
            _LOGGER.debug("OWN HMAC auth succeeded")
            return

        # Verify server confirmation token if present
        if resp and resp not in (OWN_NACK, OWN_ACK):
            token_match = re.search(r"\*#\*(\w+)", resp)
            if token_match:
                auth.verify_server(token_match.group(1))
                self._authenticated = True
                return

        raise BticinoOwnError(f"OWN auth failed: {resp}")

    async def _send_command(self, frame: str) -> str:
        """Send an OWN command and check the ACK."""
        response = await self._send_raw_frame(frame)
        _LOGGER.debug("OWN cmd %s → %s", frame, response)

        if response == OWN_NACK:
            raise BticinoOwnError(f"Gateway NACK for command: {frame}")

        return response

    async def _send_raw_frame(self, frame: str) -> str:
        """Write a frame and read back the response."""
        if not self._writer or not self._reader:
            raise BticinoOwnError("Not connected")

        _LOGGER.debug("OWN >>> %s", frame)
        self._writer.write(frame.encode())
        await self._writer.drain()

        return await self._read_frame()

    async def _read_frame(self) -> str:
        """Read bytes until the '##' terminator."""
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
