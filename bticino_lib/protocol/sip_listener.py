"""Persistent SIP/TLS listener for incoming doorbell INVITE from the C300X gateway.

Mirrors the app's Linphone registration flow (VctLinphoneService.java):
  connect TLS → REGISTER (with digest auth if challenged) → listen for INVITE
  → send 486 Busy Here → fire callback → re-register before expiry → repeat.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Callable, Optional

from ..exceptions import BticinoSipAuthError, BticinoSipError
from ..models import SipCredentials, TlsCertificates
from .sip_client import (
    _CRLF,
    _SipMessageBuilder,
    _build_ssl_context,
    _callid,
    _parse_www_auth,
    _rand_string,
    _sip_digest_response,
)

_LOGGER = logging.getLogger(__name__)

_SIP_PORT = 5061
_REGISTER_EXPIRES = 300
_REREGISTER_MARGIN = 60   # re-register this many seconds before expiry
_CONNECT_TIMEOUT = 15.0
_RECV_CHUNK = 8192


def _build_response(status: int, reason: str, invite: str, tag: str) -> str:
    """Build a minimal SIP response reusing the headers from an incoming request."""
    via_lines: list[str] = []
    headers: dict[str, str] = {}
    for line in invite.splitlines():
        low = line.lower()
        if low.startswith(("via:", "v:")):
            via_lines.append(line)
        elif ":" in line:
            k, _, v = line.partition(":")
            key = k.strip().lower()
            if key not in headers:
                headers[key] = v.strip()

    to_val = headers.get("to", "")
    if ";tag=" not in to_val:
        to_val = f"{to_val};tag={tag}"

    parts = [
        f"SIP/2.0 {status} {reason}",
        *via_lines,
        f"From: {headers.get('from', '')}",
        f"To: {to_val}",
        f"Call-ID: {headers.get('call-id', '')}",
        f"CSeq: {headers.get('cseq', '')}",
        "Content-Length: 0",
        "",
        "",
    ]
    return _CRLF.join(parts)


class BticinoSipListener:
    """Maintains a persistent SIP/TLS connection to detect incoming doorbell calls.

    After registering with the local gateway, it reads the stream continuously.
    When a SIP INVITE arrives (someone rang the doorbell), it:
      1. Responds 486 Busy Here so the gateway closes the dialog
      2. Calls on_invite() to notify Home Assistant
    Re-registers before the 300s expiry and reconnects on any error.
    """

    def __init__(
        self,
        credentials: SipCredentials,
        tls: Optional[TlsCertificates],
        local_ip: str,
        on_invite: Callable[[], None],
    ) -> None:
        self._creds = credentials
        self._tls = tls
        self._local_ip = local_ip
        self._on_invite = on_invite
        self._running = False

    def set_callback(self, on_invite: Callable[[], None]) -> None:
        self._on_invite = on_invite

    async def start(self) -> None:
        """Run forever: connect, register, listen, reconnect on error."""
        self._running = True
        while self._running:
            try:
                await self._session()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                _LOGGER.warning("SIP listener: %s — retry in 60s", exc)
                if self._running:
                    await asyncio.sleep(60)
        _LOGGER.debug("SIP listener: stopped")

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _session(self) -> None:
        host = self._local_ip or self._creds.domain
        ssl_ctx = await asyncio.get_event_loop().run_in_executor(
            None, _build_ssl_context, self._tls
        )
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, _SIP_PORT, ssl=ssl_ctx),
            timeout=_CONNECT_TIMEOUT,
        )
        _LOGGER.info("SIP listener: connected to %s:%s", host, _SIP_PORT)
        try:
            await self._register_and_listen(reader, writer)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _make_builder(self) -> _SipMessageBuilder:
        return _SipMessageBuilder(
            local_uri=self._creds.sip_uri,
            contact_host=self._creds.domain,
            contact_port=_SIP_PORT,
            use_tls=True,
        )

    async def _send(self, writer: asyncio.StreamWriter, text: str) -> None:
        _LOGGER.debug("SIP listener >>>\n%s", text)
        writer.write(text.encode("utf-8"))
        await writer.drain()

    async def _recv(self, reader: asyncio.StreamReader, timeout: float) -> str:
        """Read one SIP message. Returns '' on timeout, raises on EOF."""
        try:
            raw = await asyncio.wait_for(reader.read(_RECV_CHUNK), timeout=timeout)
        except asyncio.TimeoutError:
            return ""
        if not raw:
            raise BticinoSipError("Connection closed by gateway")
        text = raw.decode("utf-8", errors="replace")
        _LOGGER.debug("SIP listener <<<\n%s", text)
        return text

    async def _do_register(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        builder: _SipMessageBuilder,
    ) -> None:
        server_uri = f"sip:{self._creds.domain}"
        call_id = _callid()

        req = builder.register(server_uri, call_id, _REGISTER_EXPIRES)
        await self._send(writer, req)
        resp = await self._recv(reader, timeout=15.0)

        if resp.startswith("SIP/2.0 2"):
            _LOGGER.info("SIP listener: REGISTER OK (no auth)")
            return

        if "401" in resp[:20]:
            match = re.search(r"WWW-Authenticate:\s*(.*)", resp, re.IGNORECASE)
            if not match:
                raise BticinoSipAuthError("No WWW-Authenticate in 401")
            params = _parse_www_auth(match.group(1))
            digest = _sip_digest_response(
                self._creds.username,
                params.get("realm", ""),
                self._creds.password,
                "REGISTER",
                server_uri,
                params.get("nonce", ""),
            )
            auth = (
                f'Digest username="{self._creds.username}", '
                f'realm="{params.get("realm", "")}", '
                f'nonce="{params.get("nonce", "")}", '
                f'uri="{server_uri}", '
                f'response="{digest}", '
                f'algorithm={params.get("algorithm", "MD5")}'
            )
            req = builder.register(server_uri, call_id, _REGISTER_EXPIRES, auth)
            await self._send(writer, req)
            resp = await self._recv(reader, timeout=15.0)
            if resp.startswith("SIP/2.0 2"):
                _LOGGER.info("SIP listener: REGISTER OK (digest auth)")
                return
            raise BticinoSipAuthError(f"REGISTER auth failed: {resp[:200]}")

        raise BticinoSipError(f"REGISTER unexpected response: {resp[:200]}")

    async def _register_and_listen(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        builder = self._make_builder()
        await self._do_register(reader, writer, builder)

        reregister_at = (
            asyncio.get_event_loop().time() + _REGISTER_EXPIRES - _REREGISTER_MARGIN
        )

        while self._running:
            now = asyncio.get_event_loop().time()
            wait = max(5.0, reregister_at - now)

            msg = await self._recv(reader, timeout=wait)

            if msg == "":
                # Timeout → re-register
                _LOGGER.debug("SIP listener: re-registering")
                await self._do_register(reader, writer, builder)
                reregister_at = (
                    asyncio.get_event_loop().time()
                    + _REGISTER_EXPIRES
                    - _REREGISTER_MARGIN
                )
                continue

            first_line = msg.split("\r\n")[0] if "\r\n" in msg else msg[:50]

            if msg.startswith("INVITE"):
                _LOGGER.info("SIP listener: doorbell INVITE from %s", first_line)
                resp = _build_response(486, "Busy Here", msg, _rand_string(8))
                await self._send(writer, resp)
                try:
                    self._on_invite()
                except Exception as exc:
                    _LOGGER.warning("SIP listener: on_invite error: %s", exc)

            elif msg.startswith("OPTIONS"):
                resp = _build_response(200, "OK", msg, _rand_string(8))
                await self._send(writer, resp)

            else:
                _LOGGER.debug("SIP listener: ignored %s", first_line)
