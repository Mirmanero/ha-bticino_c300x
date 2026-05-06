"""Config flow for Bticino C300X integration.

Step 1 – user: email + password → login → auto-discover plant/gateway/devices/IP
Step 2 – gateway: confirm/override the discovered local IP
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

import aiohttp
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError

from .bticino_lib import BticinoApiClient
from .bticino_lib.exceptions import BticinoAuthError, BticinoConnectionError
from .const import (
    CONF_DEVICES,
    CONF_GATEWAY_ID,
    CONF_LOCAL_IP,
    CONF_OWN_PASSWORD,
    CONF_PASSWORD,
    CONF_PLANT_ID,
    CONF_SIP_DOMAIN,
    CONF_SIP_PASSWORD,
    CONF_SIP_USERNAME,
    CONF_USERNAME,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


def _ha_device_id(gateway_id: str) -> str:
    """Generate a stable 12-char hex device ID for this HA instance."""
    return hashlib.md5(f"ha-bticino-{gateway_id}".encode()).hexdigest()[:12].upper()


async def _cloud_setup(username: str, password: str) -> dict:
    """Login and auto-discover everything. Returns the full config entry data dict."""
    async with aiohttp.ClientSession() as session:
        api = BticinoApiClient(session)

        try:
            await api.login(username, password)
        except BticinoAuthError as exc:
            raise InvalidAuth from exc
        except BticinoConnectionError as exc:
            raise CannotConnect from exc

        plants = await api.get_plants()
        if not plants:
            raise NothingFound("no_plants")

        plant = plants[0]
        gateways = await api.get_gateways(plant.plant_id)
        if not gateways:
            raise NothingFound("no_gateways")

        gateway = gateways[0]

        own_password = "12345"
        try:
            gw_info = await api.get_gateway_info(plant.plant_id, gateway.gateway_id)
            own_password = gw_info.get("PswOpen") or "12345"
        except Exception:
            _LOGGER.warning("Could not fetch PswOpen, using default")

        devices: list[dict] = []
        local_ip = ""
        try:
            device_objs, local_ip = await api.get_plant_setup(
                plant.plant_id, gateway.gateway_id
            )
            devices = [d.to_dict() for d in device_objs]
        except Exception as exc:
            _LOGGER.warning("Could not fetch plant setup: %s", exc)

        sip_username = sip_password = sip_domain = ""
        try:
            device_id = _ha_device_id(gateway.gateway_id)
            sip = await api.get_sip_credentials(plant.plant_id, gateway.gateway_id, device_id)
            sip_username = sip.username
            sip_password = sip.password
            sip_domain = sip.domain
            _LOGGER.info("SIP credentials acquired for gateway %s", gateway.gateway_id)
        except Exception as exc:
            _LOGGER.warning("Could not fetch SIP credentials: %s", exc)

        return {
            CONF_USERNAME: username,
            CONF_PASSWORD: password,
            CONF_PLANT_ID: plant.plant_id,
            CONF_GATEWAY_ID: gateway.gateway_id,
            CONF_OWN_PASSWORD: own_password,
            CONF_LOCAL_IP: local_ip,
            CONF_DEVICES: devices,
            CONF_SIP_USERNAME: sip_username,
            CONF_SIP_PASSWORD: sip_password,
            CONF_SIP_DOMAIN: sip_domain,
        }


class BticinoConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Bticino C300X."""

    VERSION = 1

    def __init__(self) -> None:
        self._config: dict = {}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 1: credentials → auto-discover from cloud."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                self._config = await _cloud_setup(
                    user_input[CONF_USERNAME],
                    user_input[CONF_PASSWORD],
                )
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except NothingFound as exc:
                errors["base"] = str(exc)
            except Exception:
                _LOGGER.exception("Unexpected error during config flow")
                errors["base"] = "unknown"
            else:
                await self.async_set_unique_id(self._config[CONF_GATEWAY_ID])
                self._abort_if_unique_id_configured()
                return await self.async_step_gateway()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME): str,
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )

    async def async_step_gateway(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 2: confirm/override the discovered local IP."""
        if user_input is not None:
            self._config[CONF_LOCAL_IP] = user_input[CONF_LOCAL_IP].strip()
            return self.async_create_entry(
                title=f"C300X – {self._config[CONF_GATEWAY_ID]}",
                data=self._config,
            )

        discovered_ip = self._config.get(CONF_LOCAL_IP, "")
        device_names = ", ".join(
            d.get("name", "") for d in self._config.get(CONF_DEVICES, [])
        ) or "—"

        return self.async_show_form(
            step_id="gateway",
            data_schema=vol.Schema(
                {vol.Required(CONF_LOCAL_IP, default=discovered_ip): str}
            ),
            description_placeholders={
                "gateway_id": self._config.get(CONF_GATEWAY_ID, ""),
                "own_password": self._config.get(CONF_OWN_PASSWORD, ""),
                "devices": device_names,
            },
        )


class CannotConnect(HomeAssistantError):
    pass


class InvalidAuth(HomeAssistantError):
    pass


class NothingFound(HomeAssistantError):
    pass
