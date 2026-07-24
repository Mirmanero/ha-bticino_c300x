"""Persistent SIP/TLS listener for incoming doorbell INVITE from the C300X gateway.

The C300X always initiates the SIP INVITE (when someone rings or on monitor request).
This listener:
  - REGISTERs with the local gateway so it receives calls
  - On INVITE: fires on_invite() (doorbell sensor), then either
      - accepts with 200 OK + SDP (if a video callback is registered) so RTP flows
      - or rejects with 486 Busy Here
  - On BYE: fires on_video_end() and responds 200 OK
  - Re-registers before the 300s expiry and reconnects on any error
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
import time
from typing import Awaitable, Callable, Optional

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
_REREGISTER_MARGIN = 60
_CONNECT_TIMEOUT = 15.0
_RECV_CHUNK = 8192


def _parse_headers(msg: str) -> tuple[list[str], dict[str, str]]:
    via_lines: list[str] = []
    headers: dict[str, str] = {}
    for line in msg.splitlines():
        low = line.lower()
        if low.startswith(("via:", "v:")):
            via_lines.append(line)
        elif ":" in line:
            k, _, v = line.partition(":")
            key = k.strip().lower()
            if key not in headers:
                headers[key] = v.strip()
    return via_lines, headers


def _build_response(status: int, reason: str, request: str, tag: str) -> str:
    """Build a minimal SIP response mirroring the incoming request's headers."""
    via_lines, headers = _parse_headers(request)
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


def _build_200ok_sdp(request: str, tag: str, sdp_body: str) -> str:
    """Build a 200 OK response to an INVITE with an SDP body."""
    via_lines, headers = _parse_headers(request)
    to_val = headers.get("to", "")
    if ";tag=" not in to_val:
        to_val = f"{to_val};tag={tag}"
    body_bytes = sdp_body.encode("utf-8")
    parts = [
        "SIP/2.0 200 OK",
        *via_lines,
        f"From: {headers.get('from', '')}",
        f"To: {to_val}",
        f"Call-ID: {headers.get('call-id', '')}",
        f"CSeq: {headers.get('cseq', '')}",
        "Content-Type: application/sdp",
        f"Content-Length: {len(body_bytes)}",
        "",
        sdp_body,
    ]
    return _CRLF.join(parts)


def _parse_video_pt(msg: str) -> int:
    """Extract the first video payload type from an incoming INVITE SDP."""
    in_video = False
    for line in msg.splitlines():
        if line.startswith("m=video"):
            parts = line.split()
            if len(parts) >= 4:
                try:
                    return int(parts[3])
                except ValueError:
                    pass
            in_video = True
        elif line.startswith("m=") and in_video:
            break
    return 99  # Linphone default


def _build_video_answer_sdp(local_ip: str, video_port: int, video_pt: int) -> str:
    """SDP answer accepting video receive-only with the gateway's offered PT."""
    ts = int(time.time())
    audio_port = video_port + 2
    return "\r\n".join([
        "v=0",
        f"o=- {ts} {ts} IN IP4 {local_ip}",
        "s=-",
        f"c=IN IP4 {local_ip}",
        "t=0 0",
        f"m=audio {audio_port} RTP/AVP 0 8",
        "a=rtpmap:0 PCMU/8000",
        "a=rtpmap:8 PCMA/8000",
        "a=recvonly",
        f"m=video {video_port} RTP/AVP {video_pt}",
        f"a=rtpmap:{video_pt} H264/90000",
        "a=recvonly",
        "",
    ])


class BticinoSipListener:
    """Maintains a persistent SIP/TLS connection to detect and optionally answer
    incoming doorbell calls from the C300X gateway."""

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
        self._on_video_start: Optional[Callable[[int, str, int], Awaitable[None]]] = None
        self._on_video_end: Optional[Callable[[], None]] = None
        self._running = False

    def set_callback(self, on_invite: Callable[[], None]) -> None:
        self._on_invite = on_invite

    def set_video_callbacks(
        self,
        on_start: Optional[Callable[[int, str, int], Awaitable[None]]],
        on_end: Optional[Callable[[], None]],
    ) -> None:
        self._on_video_start = on_start
        self._on_video_end = on_end

    async def start(self) -> None:
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
                _LOGGER.info("SIP listener: doorbell INVITE — %s", first_line)
                try:
                    self._on_invite()
                except Exception as exc:
                    _LOGGER.warning("SIP listener: on_invite error: %s", exc)

                tag = _rand_string(8)
                if self._on_video_start is not None:
                    video_pt = _parse_video_pt(msg)
                    rtp_port = random.randint(9000, 9099)
                    try:
                        await self._on_video_start(rtp_port, self._local_ip, video_pt)
                        sdp = _build_video_answer_sdp(self._local_ip, rtp_port, video_pt)
                        resp = _build_200ok_sdp(msg, tag, sdp)
                        _LOGGER.info(
                            "SIP listener: accepting video call "
                            "(RTP port %d, PT %d)", rtp_port, video_pt,
                        )
                    except Exception as exc:
                        _LOGGER.error("SIP listener: video start failed → 486: %s", exc)
                        resp = _build_response(486, "Busy Here", msg, tag)
                else:
                    resp = _build_response(486, "Busy Here", msg, tag)
                await self._send(writer, resp)

            elif msg.startswith("ACK"):
                _LOGGER.debug("SIP listener: ACK (ignored)")

            elif msg.startswith("BYE"):
                _LOGGER.info("SIP listener: BYE — call ended")
                resp = _build_response(200, "OK", msg, _rand_string(8))
                await self._send(writer, resp)
                if self._on_video_end is not None:
                    try:
                        self._on_video_end()
                    except Exception as exc:
                        _LOGGER.warning("SIP listener: on_video_end error: %s", exc)

            elif msg.startswith("OPTIONS"):
                resp = _build_response(200, "OK", msg, _rand_string(8))
                await self._send(writer, resp)

            else:
                _LOGGER.debug("SIP listener: ignored %s", first_line)
