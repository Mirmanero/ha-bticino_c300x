"""Minimal asyncio SIP/TLS client for sending door-open OWN commands.

Sequence:
  1. Connect via TLS to {local_ip}:5061
  2. REGISTER (digest auth if challenged)
  3. MESSAGE sip:c300x@{domain} with the OWN frame as body (e.g. *8*19*20##)
  4. Repeat for close frame
  5. Close connection
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
import os
from typing import Optional

from ..exceptions import BticinoSipAuthError, BticinoSipError
from ..models import SipCredentials, TlsCertificates

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


def _build_ssl_context(tls: Optional[TlsCertificates] = None) -> ssl.SSLContext:
    """Build an SSL context permissive enough for the gateway's embedded TLS stack."""
    _LOGGER.debug(
        "SSL: OpenSSL version = %s", ssl.OPENSSL_VERSION
    )

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    _LOGGER.debug("SSL: check_hostname=False, verify_mode=CERT_NONE")

    # Allow all cipher suites including legacy ones
    for cipher_str in ("ALL:@SECLEVEL=0", "DEFAULT:@SECLEVEL=0"):
        try:
            ctx.set_ciphers(cipher_str)
            _LOGGER.debug("SSL: ciphers set to %r", cipher_str)
            break
        except ssl.SSLError as exc:
            _LOGGER.debug("SSL: set_ciphers(%r) failed: %s", cipher_str, exc)

    # Try to re-enable TLS 1.0 / 1.1
    for flag_name in ("OP_NO_TLSv1", "OP_NO_TLSv1_1"):
        flag = getattr(ssl, flag_name, None)
        if flag is None:
            _LOGGER.debug("SSL: flag %s not present in ssl module", flag_name)
            continue
        old = ctx.options
        try:
            ctx.options &= ~flag
            if ctx.options != old:
                _LOGGER.debug("SSL: cleared %s (options %08x → %08x)", flag_name, old, ctx.options)
            else:
                _LOGGER.debug("SSL: %s was already clear", flag_name)
        except Exception as exc:
            _LOGGER.debug("SSL: could not clear %s: %s", flag_name, exc)

    # Try setting minimum TLS version
    for ver_name in ("TLSv1", "TLSv1_1", "TLSv1_2"):
        ver = getattr(ssl.TLSVersion, ver_name, None)
        if ver is None:
            _LOGGER.debug("SSL: TLSVersion.%s not available", ver_name)
            continue
        try:
            ctx.minimum_version = ver
            _LOGGER.debug("SSL: minimum_version set to TLSVersion.%s", ver_name)
            break
        except (AttributeError, ValueError, ssl.SSLError) as exc:
            _LOGGER.debug("SSL: cannot set minimum_version=%s: %s", ver_name, exc)

    # Log current min/max version if readable
    try:
        _LOGGER.debug(
            "SSL: effective minimum_version=%s maximum_version=%s",
            ctx.minimum_version, ctx.maximum_version,
        )
    except Exception:
        pass

    has_cert = bool(tls and tls.client_cert_pem and tls.client_key_pem)
    _LOGGER.debug(
        "SSL: client_cert present=%s ca_cert present=%s",
        has_cert,
        bool(tls and tls.ca_cert_pem),
    )

    if has_cert:
        cert_file = key_file = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as cf:
                cf.write(tls.client_cert_pem)
                cert_file = cf.name
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as kf:
                kf.write(tls.client_key_pem)
                key_file = kf.name
            ctx.load_cert_chain(cert_file, key_file)
            _LOGGER.debug("SSL: mutual TLS — client certificate loaded OK")
        except Exception as exc:
            _LOGGER.warning("SSL: could not load client certificate: %s", exc)
        finally:
            for path in (cert_file, key_file):
                if path:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass

    return ctx


class _SipMessageBuilder:
    def __init__(
        self,
        local_uri: str,
        contact_host: str,
        contact_port: int = 5061,
        use_tls: bool = True,
    ) -> None:
        self.local_uri = local_uri
        transport = "TLS" if use_tls else "TCP"
        self.contact = f"<sip:{contact_host}:{contact_port};transport={transport}>"
        self._transport = transport
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
            f"Via: SIP/2.0/{self._transport} {self.contact[1:-1]};branch={via_branch}",
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
            f"Via: SIP/2.0/{self._transport} {self.contact[1:-1]};branch={via_branch}",
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
    """Async SIP/TLS client for Bticino C300X door activation."""

    def __init__(
        self,
        credentials: SipCredentials,
        tls: Optional[TlsCertificates] = None,
        local_ip: Optional[str] = None,
        sip_port: int = 5061,
        use_tls: bool = True,
        timeout: float = 15.0,
    ) -> None:
        self._creds = credentials
        self._tls = tls
        self._local_ip = local_ip
        self._port = sip_port
        self._use_tls = use_tls
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
        proto = "TLS" if self._use_tls else "TCP"
        if self._use_tls:
            # _build_ssl_context writes temp files + calls load_cert_chain — run off event loop
            ssl_ctx = await asyncio.get_event_loop().run_in_executor(
                None, _build_ssl_context, self._tls
            )
        else:
            ssl_ctx = None

        _LOGGER.debug(
            "SIP connect: host=%s port=%s proto=%s sip_uri=%s domain=%s",
            host, self._port, proto, self._creds.sip_uri, self._creds.domain,
        )

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(host, self._port, ssl=ssl_ctx),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError as exc:
            _LOGGER.error("SIP connect timeout to %s:%s", host, self._port)
            raise BticinoSipError(f"Timeout connecting to {host}:{self._port}") from exc
        except OSError as exc:
            _LOGGER.error("SIP connect OSError to %s:%s: %s", host, self._port, exc)
            raise BticinoSipError(f"Cannot connect to {host}:{self._port}: {exc}") from exc

        # Log TLS handshake details
        if self._use_tls and self._writer:
            try:
                ssl_obj = self._writer.get_extra_info("ssl_object")
                if ssl_obj:
                    cipher = ssl_obj.cipher()
                    _LOGGER.debug(
                        "SIP TLS handshake OK: version=%s cipher=%s bits=%s",
                        ssl_obj.version(), cipher[0] if cipher else "?",
                        cipher[2] if cipher else "?",
                    )
                    peer_cert = ssl_obj.getpeercert(binary_form=False)
                    _LOGGER.debug("SIP TLS peer cert: %s", peer_cert or "(none/unverified)")
            except Exception as exc:
                _LOGGER.debug("SIP TLS info not available: %s", exc)

        _LOGGER.debug("SIP %s connection established to %s:%s", proto, host, self._port)

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
            _LOGGER.info("SIP MESSAGE OK: body=%r target=%s", body, target_uri)
            return

        if "401" in response[:20]:
            _LOGGER.debug("SIP MESSAGE 401 — retrying with digest auth")
            auth_header = self._build_digest(response, "MESSAGE", target_uri)
            request = builder.message(target_uri, body, call_id, auth_header)
            response = await self._send_recv(request)
            if response.startswith("SIP/2.0 2"):
                _LOGGER.info("SIP MESSAGE OK (digest retry): body=%r", body)
                return
            _LOGGER.error("SIP MESSAGE auth failed, full response:\n%s", response)
            raise BticinoSipAuthError(f"SIP MESSAGE auth failed: {response[:200]}")

        _LOGGER.error("SIP MESSAGE unexpected response:\n%s", response)
        raise BticinoSipError(f"Unexpected MESSAGE response: {response[:200]}")

    async def _register(self, expires: int = 300) -> None:
        server_uri = f"sip:{self._creds.domain}"
        builder = self._make_builder()
        call_id = _callid()

        _LOGGER.debug("SIP REGISTER → %s (expires=%s)", server_uri, expires)
        request = builder.register(server_uri, call_id, expires)
        response = await self._send_recv(request)

        if response.startswith("SIP/2.0 2"):
            self._registered = True
            _LOGGER.debug("SIP REGISTER OK (no auth)")
            return

        if "401" in response[:20]:
            _LOGGER.debug("SIP REGISTER 401 — retrying with digest auth")
            auth_header = self._build_digest(response, "REGISTER", server_uri)
            request = builder.register(server_uri, call_id, expires, auth_header)
            response = await self._send_recv(request)
            if response.startswith("SIP/2.0 2"):
                self._registered = True
                _LOGGER.debug("SIP REGISTER OK (digest)")
                return
            _LOGGER.error("SIP REGISTER auth failed, full response:\n%s", response)
            raise BticinoSipAuthError(f"SIP REGISTER failed: {response[:200]}")

        _LOGGER.error("SIP REGISTER unexpected response:\n%s", response)
        raise BticinoSipError(f"Unexpected REGISTER response: {response[:200]}")

    def _make_builder(self) -> _SipMessageBuilder:
        # Use the SIP domain (not the local IP) in Via/Contact headers — same as Linphone
        # which uses "domain;maddr=local_ip" so headers carry the domain name.
        contact_host = self._creds.domain
        return _SipMessageBuilder(
            local_uri=self._creds.sip_uri,
            contact_host=contact_host,
            contact_port=self._port,
            use_tls=self._use_tls,
        )

    def _build_digest(self, challenge_response: str, method: str, uri: str) -> str:
        match = re.search(r"WWW-Authenticate:\s*(.*)", challenge_response, re.IGNORECASE)
        if not match:
            raise BticinoSipAuthError("No WWW-Authenticate header in 401 response")
        params = _parse_www_auth(match.group(1))
        _LOGGER.debug(
            "SIP digest: realm=%r nonce=%r algorithm=%r",
            params.get("realm"), params.get("nonce"), params.get("algorithm"),
        )
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
        _LOGGER.debug("SIP >>>\n%s", request)
        self._writer.write(request.encode("utf-8"))
        await self._writer.drain()
        try:
            raw = await asyncio.wait_for(self._reader.read(8192), timeout=self._timeout)
        except asyncio.TimeoutError as exc:
            raise BticinoSipError("Timeout waiting for SIP response") from exc
        response = raw.decode("utf-8", errors="replace")
        _LOGGER.debug("SIP <<<\n%s", response)
        return response
