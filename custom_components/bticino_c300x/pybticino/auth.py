"""Authentication against the Bticino cloud portal (myhomeweb.com)."""

from __future__ import annotations

import logging
from typing import Optional

import aiohttp

from .const import (
    APP_VERSION,
    APP_VERSION_PREFIX,
    CONTENT_TYPE_JSON,
    HEADER_AUTH_TOKEN,
    HEADER_CONTENT_TYPE,
    HEADER_PRJ_NAME,
    PORTAL_BASE_URL,
    PRJ_NAME,
    API_SIGN_IN,
    API_USER,
)
from .exceptions import BticinoAuthError, BticinoApiError, BticinoConnectionError
from .models import AuthToken, UserInfo

_LOGGER = logging.getLogger(__name__)


class BticinoAuth:
    """Manages authentication tokens against the Bticino cloud portal."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        base_url: str = PORTAL_BASE_URL,
    ) -> None:
        self._session = session
        self._base_url = base_url.rstrip("/")
        self._token: Optional[str] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def token(self) -> Optional[str]:
        return self._token

    async def login(self, username: str, password: str) -> AuthToken:
        """Authenticate and store the auth token.

        Replicates POST /eliot/users/sign_in from the app.
        """
        payload = {
            "username": username,
            "pwd": password,
            "appVersion": f"{APP_VERSION_PREFIX}{APP_VERSION}",
        }
        _LOGGER.debug("Logging in as %s", username)

        data = await self._request(
            "POST",
            API_SIGN_IN,
            json=payload,
            authenticated=False,
        )

        token = data.get("auth_token")
        if not token:
            raise BticinoAuthError("Login response did not contain auth_token")

        self._token = token
        _LOGGER.debug("Login successful, token acquired")
        return AuthToken(token=token)

    async def get_user_info(self) -> UserInfo:
        """Return basic info about the authenticated user."""
        data = await self._request("GET", API_USER)
        try:
            return UserInfo(
                user_id=data["id"],
                username=data.get("username", ""),
                email=data.get("email", ""),
            )
        except KeyError as exc:
            raise BticinoApiError(f"Unexpected user response: {data}") from exc

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_headers(self, authenticated: bool = True) -> dict:
        headers: dict = {
            HEADER_PRJ_NAME: PRJ_NAME,
            HEADER_CONTENT_TYPE: CONTENT_TYPE_JSON,
        }
        if authenticated:
            if not self._token:
                raise BticinoAuthError("Not authenticated. Call login() first.")
            headers[HEADER_AUTH_TOKEN] = self._token
        return headers

    async def _request_raw(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        authenticated: bool = True,
        extra_headers: dict | None = None,
    ) -> str:
        """Like _request but returns raw response text (for binary/base64 responses)."""
        url = f"{self._base_url}{path}"
        headers = self._build_headers(authenticated)
        if extra_headers:
            headers.update(extra_headers)
        try:
            async with self._session.request(
                method, url, headers=headers, params=params, ssl=True
            ) as resp:
                _LOGGER.debug("%s %s -> %s (raw)", method, url, resp.status)
                if resp.status == 401:
                    self._token = None
                    raise BticinoAuthError(f"Authentication error on {method} {path} (HTTP 401)")
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
    ) -> dict:
        url = f"{self._base_url}{path}"
        headers = self._build_headers(authenticated)
        if extra_headers:
            headers.update(extra_headers)

        try:
            async with self._session.request(
                method,
                url,
                headers=headers,
                json=json,
                params=params,
                ssl=True,
            ) as resp:
                _LOGGER.debug("%s %s → %s", method, url, resp.status)

                if resp.status == 401:
                    self._token = None
                    raise BticinoAuthError(
                        f"Authentication error on {method} {path} (HTTP 401)"
                    )
                if resp.status == 403:
                    raise BticinoAuthError(
                        f"Access denied on {method} {path} (HTTP 403)"
                    )
                if resp.status >= 400:
                    text = await resp.text()
                    raise BticinoApiError(
                        f"API error {resp.status} on {method} {path}: {text}",
                        status_code=resp.status,
                    )

                text = await resp.text()
                try:
                    import json as _json
                    body = _json.loads(text) if text.strip() else {}
                except Exception:
                    body = {}
                if body is None:
                    body = {}

                # Il server Bticino restituisce auth_token nell'header, non nel body
                if (
                    HEADER_AUTH_TOKEN in resp.headers
                    and isinstance(body, dict)
                    and not body.get(HEADER_AUTH_TOKEN)
                ):
                    body[HEADER_AUTH_TOKEN] = resp.headers[HEADER_AUTH_TOKEN]

                return body

        except aiohttp.ClientConnectionError as exc:
            raise BticinoConnectionError(
                f"Cannot connect to {self._base_url}"
            ) from exc
