"""OWN local protocol client for Bticino C300X (TCP port 20000).

Connects directly to the gateway on the LAN — no cloud, no SIP.
The gateway uses BTicino Open Web Net text protocol:

  Frame format:  *WHO*WHAT*WHERE##
  ACK:           *#*1##
  NACK:          *#*0##

Handshake (from decompiled h0/k.java):
  1. Gateway sends *#*1##
  2. Client sends *99*0## (CMD session)
  3a. Gateway sends *#*1## → connected, no auth
  3b. Gateway sends a challenge number → client sends *#<hash(challenge,pwd)>## → gateway ACKs

The challenge hash is implemented in f0/b.java (BTOpenPassword):
a sequence of 32-bit rotate/byteswap/NOT operations, one per digit in the challenge.
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


def _open_pwd_hash(challenge: str, password: str) -> str:
    """Implement f0.b.a() — BTOpenPassword challenge-response hash.

    Each digit in the challenge applies a 32-bit operation on the accumulator
    (rotate, byte-swap, NOT). Derived from f0/b.java in the decompiled app.
    """
    try:
        acc = int(password)
    except ValueError:
        acc = 0

    first = True

    for c in challenge:
        acc &= 0xFFFFFFFF

        if c == '1':
            if first: acc = int(password) & 0xFFFFFFFF
            j8 = (acc & 0xFFFFFF80) >> 7
            acc = (j8 + ((acc << 25) & 0xFFFFFFFF)) & 0xFFFFFFFF
        elif c == '2':
            if first: acc = int(password) & 0xFFFFFFFF
            j8 = (acc & 0xFFFFFFF0) >> 4
            acc = (j8 + ((acc << 28) & 0xFFFFFFFF)) & 0xFFFFFFFF
        elif c == '3':
            if first: acc = int(password) & 0xFFFFFFFF
            j8 = (acc & 0xFFFFFFF8) >> 3
            acc = (j8 + ((acc << 29) & 0xFFFFFFFF)) & 0xFFFFFFFF
        elif c == '4':
            if first: acc = int(password) & 0xFFFFFFFF
            j8 = (acc << 1) & 0xFFFFFFFF
            acc = (j8 + (acc >> 31)) & 0xFFFFFFFF
        elif c == '5':
            if first: acc = int(password) & 0xFFFFFFFF
            j8 = (acc << 5) & 0xFFFFFFFF
            acc = (j8 + (acc >> 27)) & 0xFFFFFFFF
        elif c == '6':
            if first: acc = int(password) & 0xFFFFFFFF
            j8 = (acc << 12) & 0xFFFFFFFF
            acc = (j8 + (acc >> 20)) & 0xFFFFFFFF
        elif c == '7':
            if first: acc = int(password) & 0xFFFFFFFF
            j8 = (acc & 0xFF00) + ((acc & 0xFF) << 24) + ((acc & 0xFF0000) >> 16)
            j10 = (acc & 0xFF000000) >> 8
            acc = (j8 + j10) & 0xFFFFFFFF
        elif c == '8':
            if first: acc = int(password) & 0xFFFFFFFF
            j8 = ((acc & 0xFFFF) << 16) + (acc >> 24)
            j10 = (acc & 0xFF0000) >> 8
            acc = (j8 + j10) & 0xFFFFFFFF
        elif c == '9':
            if first: acc = int(password) & 0xFFFFFFFF
            acc = (~acc) & 0xFFFFFFFF
        else:
            continue  # non-digit: skip without clearing 'first'

        first = False

    return str(acc & 0xFFFFFFFF)


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
        _LOGGER.info("OWN cmd %s -> %s", frame, response)
        if response == OWN_NACK:
            raise BticinoOwnError(f"Gateway NACK for command: {frame}")
        return response

    async def _handshake(self) -> None:
        """OWN connection handshake.

        Standard BTicino flow:
          1. Gateway sends *#*1## (hello)
          2. Client sends *99*0## (request command session)
          3. Gateway sends *#*1## (session ready)
        If the gateway challenges with *98*/*99*, do password auth first.
        """
        welcome = await self._read_frame()
        _LOGGER.info("OWN [%s] welcome: %s", self._host, welcome)

        if welcome == OWN_NACK:
            raise BticinoOwnError("Gateway refused connection (*#*0##)")

        if "*98*" in welcome or "*99*" in welcome:
            await self._authenticate(welcome)
            await self._negotiate_command_session()
            return

        if welcome == OWN_ACK:
            await self._negotiate_command_session()
            return

        _LOGGER.warning("OWN [%s] unexpected welcome %r — trying *99*0## anyway", self._host, welcome)
        await self._negotiate_command_session()

    async def _negotiate_command_session(self) -> None:
        """Send *99*0## to open a CMD session, handle optional password challenge.

        From k.java (BTOpenLink):
          - ACK (*#*1##)  → ready, no auth needed
          - challenge      → compute *#<f0.b.a(challenge, password)>## and wait for ACK
          - NACK           → refused
        """
        resp = await self._send_raw_frame("*99*0##")
        _LOGGER.info("OWN [%s] CMD session (*99*0##) -> %s", self._host, resp)

        if resp == OWN_ACK:
            return
        if resp == OWN_NACK:
            raise BticinoOwnError("Gateway refused command session (*99*0##)")

        # *98*N## is a session-mode/version frame (WHO=98 is OWN session management).
        # Sending a BTOpenPassword hash in response makes the gateway close the connection.
        # Treat it as "session accepted, proceed".
        if re.match(r'^\*98\*\d+##$', resp):
            _LOGGER.info("OWN [%s] session mode frame %s — proceeding without auth", self._host, resp)
            return

        # Numeric challenge: compute BTOpenPassword hash and respond.
        challenge_match = re.search(r'\*(\d+)##', resp)
        challenge = challenge_match.group(1) if challenge_match else resp.strip().replace("#", "").replace("*", "").replace("|", "")
        _LOGGER.info("OWN [%s] password challenge: %r -> computing hash", self._host, challenge)

        if not challenge:
            _LOGGER.warning("OWN [%s] empty challenge after *99*0##, proceeding without auth", self._host)
            return

        hashed = _open_pwd_hash(challenge, self._password)
        ack = await self._send_raw_frame(f"*#{hashed}##")
        _LOGGER.info("OWN [%s] auth response: %s", self._host, ack)

        if ack == OWN_NACK:
            raise BticinoOwnError("Gateway rejected CMD session password (wrong PswOpen?)")
        if ack != OWN_ACK:
            _LOGGER.warning("OWN [%s] unexpected auth response %r — proceeding anyway", self._host, ack)

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
