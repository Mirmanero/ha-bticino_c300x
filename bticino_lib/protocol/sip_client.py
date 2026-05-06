"""Minimal asyncio SIP/TLS client for sending door-open OWN commands.

Sequence:
  1. Connect via TLS to {local_ip}:5061 (local) or {domain}:5061 (remote)
  2. REGISTER (digest auth if challenged)
  3. MESSAGE sip:c300x@{domain} with the OWN frame as body (e.g. *8*19*21##)
  4. Repeat for close frame
  5. De-register and close
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import re
import ssl
import string
from typing import Optional

from ..exceptions import BticinoSipAuthError, BticinoSipError
from ..models import SipCredentials

_LOGGER = logging.getLogger(__name__)

_CRLF = "\r\n"


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
) -> str:
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    return hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()


def _parse_www_auth(header_value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for match in re.finditer(r'(\w+)="([^"]*)"', header_value):
        result[match.group(1)] = match.group(2)
    for match in re.finditer(r'(\w+)=([^",\s]+)', header_value):
        if match.group(1) not in result:
            result[match.group(1)] = match.group(2)
    return result


def _build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _SipMessageBuilder:
    def __init__(self, local_uri: str, contact_host: str, contact_port: int = 5061) -> None:
        self.local_uri = local_uri
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
            f"Expires: {expires}",
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


class BticinoSipClient:
    """Async SIP/TLS client for Bticino C300X door activation.

    Usage::

        async with BticinoSipClient(sip_creds, local_ip="192.168.1.50") as client:
            await client.send_message("sip:c300x@ABCDEF.bs.iotleg.com", "*8*19*21##")
    """

    def __init__(
        self,
        credentials: SipCredentials,
        local_ip: Optional[str] = None,
        sip_port: int = 5061,
        timeout: float = 15.0,
    ) -> None:
        self._creds = credentials
        self._local_ip = local_ip
        self._port = sip_port
        self._timeout = timeout
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._registered = False

    async def __aenter__(self) -> "BticinoSipClient":
        await self.connect()
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    async def connect(self) -> None:
        host = self._local_ip or self._creds.domain
        ssl_ctx = _build_ssl_context()
        _LOGGER.debug("SIP connecting to %s:%s", host, self._port)
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

    async def send_message(self, target_uri: str, body: str) -> None:
        if not self._registered:
            await self._register()

        builder = self._make_builder()
        call_id = _callid()
        request = builder.message(target_uri, body, call_id)
        response = await self._send_recv(request)

        if response.startswith("SIP/2.0 2"):
            _LOGGER.info("SIP MESSAGE delivered: %s → %s", body, target_uri)
            return

        if "401" in response[:20]:
            auth_header = self._build_digest(response, "MESSAGE", target_uri)
            request = builder.message(target_uri, body, call_id, auth_header)
            response = await self._send_recv(request)
            if response.startswith("SIP/2.0 2"):
                _LOGGER.info("SIP MESSAGE (retry) delivered: %s → %s", body, target_uri)
                return
            raise BticinoSipAuthError(f"SIP MESSAGE auth failed: {response[:80]}")

        raise BticinoSipError(f"Unexpected MESSAGE response: {response[:80]}")

    async def _register(self, expires: int = 300) -> None:
        server_uri = f"sip:{self._creds.domain}"
        builder = self._make_builder()
        call_id = _callid()

        request = builder.register(server_uri, call_id, expires)
        response = await self._send_recv(request)

        if response.startswith("SIP/2.0 2"):
            self._registered = True
            _LOGGER.debug("SIP REGISTER succeeded")
            return

        if "401" in response[:20]:
            auth_header = self._build_digest(response, "REGISTER", server_uri)
            request = builder.register(server_uri, call_id, expires, auth_header)
            response = await self._send_recv(request)
            if response.startswith("SIP/2.0 2"):
                self._registered = True
                _LOGGER.debug("SIP REGISTER (digest) succeeded")
                return
            raise BticinoSipAuthError(f"SIP REGISTER failed: {response[:80]}")

        raise BticinoSipError(f"Unexpected REGISTER response: {response[:80]}")

    def _make_builder(self) -> _SipMessageBuilder:
        contact_host = self._local_ip or self._creds.domain
        return _SipMessageBuilder(
            local_uri=self._creds.sip_uri,
            contact_host=contact_host,
            contact_port=self._port,
        )

    def _build_digest(self, challenge_response: str, method: str, uri: str) -> str:
        match = re.search(r"WWW-Authenticate:\s*(.*)", challenge_response, re.IGNORECASE)
        if not match:
            raise BticinoSipAuthError("No WWW-Authenticate header in 401 response")
        params = _parse_www_auth(match.group(1))
        digest = _sip_digest_response(
            self._creds.username,
            params.get("realm", ""),
            self._creds.password,
            method,
            uri,
            params.get("nonce", ""),
        )
        return (
            f'Digest username="{self._creds.username}", '
            f'realm="{params.get("realm", "")}", '
            f'nonce="{params.get("nonce", "")}", '
            f'uri="{uri}", '
            f'response="{digest}", '
            f'algorithm={params.get("algorithm", "MD5")}'
        )

    async def _send_recv(self, request: str) -> str:
        if not self._writer or not self._reader:
            raise BticinoSipError("Not connected")
        _LOGGER.debug("SIP >>>\n%s", request[:300])
        self._writer.write(request.encode("utf-8"))
        await self._writer.drain()
        try:
            raw = await asyncio.wait_for(self._reader.read(4096), timeout=self._timeout)
        except asyncio.TimeoutError as exc:
            raise BticinoSipError("Timeout waiting for SIP response") from exc
        response = raw.decode("utf-8", errors="replace")
        _LOGGER.debug("SIP <<<\n%s", response[:300])
        return response
