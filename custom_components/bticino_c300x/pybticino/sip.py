"""Minimal asyncio SIP client for sending door-open commands.

Implements only what is needed:
  1. REGISTER to SIP server (with TLS + digest auth)
  2. MESSAGE to sip:c300x@{gateway} (with the DTMF command in the body)
  3. De-register on close

No full SIP stack is needed because the door command is a one-shot
SIP MESSAGE, not a real-time media call.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import re
import ssl
import string
import tempfile
import time
from typing import Optional

from .exceptions import BticinoSipAuthError, BticinoSipError
from .models import SipCredentials, TlsCertificates

_LOGGER = logging.getLogger(__name__)

_CRLF = "\r\n"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rand_string(n: int = 10) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _callid() -> str:
    return f"{_rand_string(16)}@bticino-ha"


def _sip_digest_response(
    username: str,
    realm: str,
    password: str,
    method: str,
    uri: str,
    nonce: str,
    algorithm: str = "MD5",
) -> str:
    """RFC 3261 digest authentication."""
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    return hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()


def _parse_www_auth(header_value: str) -> dict[str, str]:
    """Parse WWW-Authenticate or Proxy-Authenticate header."""
    result: dict[str, str] = {}
    for match in re.finditer(r'(\w+)="([^"]*)"', header_value):
        result[match.group(1)] = match.group(2)
    for match in re.finditer(r'(\w+)=([^",\s]+)', header_value):
        if match.group(1) not in result:
            result[match.group(1)] = match.group(2)
    return result


def _build_ssl_context(tls: Optional[TlsCertificates]) -> ssl.SSLContext:
    """Build an SSL context, optionally with mutual TLS client certificate."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # gateway uses self-signed cert

    if tls and tls.client_cert_pem and tls.client_key_pem:
        # write to temp files because ssl module needs file paths
        with (
            tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as cert_f,
            tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as key_f,
        ):
            cert_f.write(tls.client_cert_pem)
            key_f.write(tls.client_key_pem)
            cert_path, key_path = cert_f.name, key_f.name
        ctx.load_cert_chain(cert_path, key_path)
        _LOGGER.debug("Mutual TLS configured with client certificate")

    return ctx


# ---------------------------------------------------------------------------
# SIP message builder
# ---------------------------------------------------------------------------

class _SipMessageBuilder:
    """Builds raw SIP requests as text strings."""

    def __init__(
        self,
        local_uri: str,
        contact_host: str,
        contact_port: int = 5061,
    ) -> None:
        self.local_uri = local_uri    # e.g. sip:user@domain.bs.iotleg.com
        self.contact = f"<sip:{contact_host}:{contact_port};transport=TLS>"
        self._cseq = 0

    def _next_cseq(self, method: str) -> str:
        self._cseq += 1
        return f"{self._cseq} {method}"

    def register(
        self,
        server_uri: str,
        call_id: str,
        expires: int = 300,
        authorization: Optional[str] = None,
    ) -> str:
        via_branch = f"z9hG4bK{_rand_string(8)}"
        cseq = self._next_cseq("REGISTER")
        lines = [
            f"REGISTER {server_uri} SIP/2.0",
            f"Via: SIP/2.0/TLS {self.contact[1:-1]};branch={via_branch}",
            f"From: <{self.local_uri}>;tag={_rand_string(8)}",
            f"To: <{self.local_uri}>",
            f"Call-ID: {call_id}",
            f"CSeq: {cseq}",
            f"Contact: {self.contact};expires={expires}",
            "Max-Forwards: 70",
            "Expires: " + str(expires),
        ]
        if authorization:
            lines.append(f"Authorization: {authorization}")
        lines += ["Content-Length: 0", "", ""]
        return _CRLF.join(lines)

    def message(
        self,
        target_uri: str,
        body: str,
        call_id: str,
        authorization: Optional[str] = None,
    ) -> str:
        via_branch = f"z9hG4bK{_rand_string(8)}"
        cseq = self._next_cseq("MESSAGE")
        body_bytes = body.encode("utf-8")
        lines = [
            f"MESSAGE {target_uri} SIP/2.0",
            f"Via: SIP/2.0/TLS {self.contact[1:-1]};branch={via_branch}",
            f"From: <{self.local_uri}>;tag={_rand_string(8)}",
            f"To: <{target_uri}>",
            f"Call-ID: {call_id}",
            f"CSeq: {cseq}",
            "Max-Forwards: 70",
            "Content-Type: text/plain",
            f"Content-Length: {len(body_bytes)}",
        ]
        if authorization:
            lines.append(f"Authorization: {authorization}")
        lines += ["", body]
        return _CRLF.join(lines)


# ---------------------------------------------------------------------------
# SIP connection
# ---------------------------------------------------------------------------

class BticinoSipClient:
    """Async SIP client that registers and sends MESSAGE requests.

    Usage::

        async with BticinoSipClient(sip_creds, tls_certs) as client:
            await client.send_message("sip:c300x@ABCDEF.bs.iotleg.com", "*8*19*4##")
    """

    def __init__(
        self,
        credentials: SipCredentials,
        tls: Optional[TlsCertificates] = None,
        local_ip: Optional[str] = None,
        sip_port: int = 5061,
        timeout: float = 15.0,
    ) -> None:
        self._creds = credentials
        self._tls = tls
        self._local_ip = local_ip
        self._port = sip_port
        self._timeout = timeout

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._registered = False

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "BticinoSipClient":
        await self.connect()
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Connect / close
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open the TLS connection to the SIP server."""
        host = self._resolve_sip_host()
        ssl_ctx = _build_ssl_context(self._tls)

        _LOGGER.debug("Connecting to SIP server %s:%s", host, self._port)
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(host, self._port, ssl=ssl_ctx),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError as exc:
            raise BticinoSipError(f"Timeout connecting to {host}:{self._port}") from exc
        except OSError as exc:
            raise BticinoSipError(f"Cannot connect to {host}:{self._port}: {exc}") from exc

        _LOGGER.debug("SIP TLS connection established")

    async def close(self) -> None:
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None
            self._registered = False

    # ------------------------------------------------------------------
    # Public operations
    # ------------------------------------------------------------------

    async def register(self, expires: int = 300) -> None:
        """SIP REGISTER (with digest auth if challenged)."""
        server_uri = self._sip_server_uri()
        builder = self._make_builder()
        call_id = _callid()

        # First attempt (no auth)
        request = builder.register(server_uri, call_id, expires)
        response = await self._send_recv(request)

        if response.startswith("SIP/2.0 200"):
            self._registered = True
            _LOGGER.debug("SIP REGISTER succeeded")
            return

        if response.startswith("SIP/2.0 401"):
            auth_header = self._build_digest(response, "REGISTER", server_uri)
            request = builder.register(server_uri, call_id, expires, auth_header)
            response = await self._send_recv(request)

            if response.startswith("SIP/2.0 200"):
                self._registered = True
                _LOGGER.debug("SIP REGISTER with digest succeeded")
                return

            raise BticinoSipAuthError(
                f"SIP REGISTER digest auth failed: {response[:60]}"
            )

        raise BticinoSipError(f"Unexpected REGISTER response: {response[:80]}")

    async def send_message(self, target_uri: str, body: str) -> None:
        """Send a SIP MESSAGE to target_uri with body (the DTMF command)."""
        if not self._registered:
            await self.register()

        builder = self._make_builder()
        call_id = _callid()

        request = builder.message(target_uri, body, call_id)
        response = await self._send_recv(request)

        if response.startswith("SIP/2.0 200"):
            _LOGGER.debug("SIP MESSAGE delivered to %s", target_uri)
            return

        if response.startswith("SIP/2.0 401"):
            auth_header = self._build_digest(response, "MESSAGE", target_uri)
            request = builder.message(target_uri, body, call_id, auth_header)
            response = await self._send_recv(request)

            if response.startswith("SIP/2.0 200"):
                _LOGGER.debug("SIP MESSAGE (retry) delivered to %s", target_uri)
                return

            raise BticinoSipAuthError(
                f"SIP MESSAGE auth failed: {response[:60]}"
            )

        raise BticinoSipError(f"Unexpected MESSAGE response: {response[:80]}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_sip_host(self) -> str:
        """Return the actual TCP host to connect to.

        For local mode the host is the gateway's LAN IP but the SIP
        domain stays as {gwid}.bs.iotleg.com  (maddr-style routing).
        """
        return self._local_ip or self._creds.domain

    def _sip_server_uri(self) -> str:
        return f"sip:{self._creds.domain}"

    def _make_builder(self) -> _SipMessageBuilder:
        contact_host = self._local_ip or self._creds.domain
        return _SipMessageBuilder(
            local_uri=self._creds.sip_uri,
            contact_host=contact_host,
            contact_port=self._port,
        )

    def _build_digest(
        self, challenge_response: str, method: str, uri: str
    ) -> str:
        """Parse the 401 challenge and compute the Authorization header."""
        match = re.search(r"WWW-Authenticate:\s*(.*)", challenge_response, re.IGNORECASE)
        if not match:
            raise BticinoSipAuthError("No WWW-Authenticate header in 401 response")

        params = _parse_www_auth(match.group(1))
        realm = params.get("realm", "")
        nonce = params.get("nonce", "")
        algorithm = params.get("algorithm", "MD5")

        digest = _sip_digest_response(
            self._creds.username,
            realm,
            self._creds.password,
            method,
            uri,
            nonce,
            algorithm,
        )

        return (
            f'Digest username="{self._creds.username}", '
            f'realm="{realm}", '
            f'nonce="{nonce}", '
            f'uri="{uri}", '
            f'response="{digest}", '
            f'algorithm={algorithm}'
        )

    async def _send_recv(self, request: str) -> str:
        """Write a SIP request and read back the response."""
        if not self._writer or not self._reader:
            raise BticinoSipError("Not connected")

        _LOGGER.debug("SIP >>>\n%s", request[:200])
        self._writer.write(request.encode("utf-8"))
        await self._writer.drain()

        try:
            raw = await asyncio.wait_for(
                self._reader.read(4096),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError as exc:
            raise BticinoSipError("Timeout waiting for SIP response") from exc

        response = raw.decode("utf-8", errors="replace")
        _LOGGER.debug("SIP <<<\n%s", response[:200])
        return response
