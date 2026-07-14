"""Binary sensor for Bticino C300X doorbell detection (incoming SIP INVITE)."""

from __future__ import annotations

import logging

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo as HaDeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_call_later

from .const import DATA_DOORBELL_LISTENER, DATA_OWN_PARAMS, DOMAIN

_LOGGER = logging.getLogger(__name__)

_DOORBELL_ON_SECONDS = 5.0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data = hass.data[DOMAIN][entry.entry_id]
    sensor = BticinoDoorbellSensor(data[DATA_OWN_PARAMS], entry.entry_id)
    async_add_entities([sensor])

    listener = data.get(DATA_DOORBELL_LISTENER)
    if listener is not None:
        listener.set_callback(sensor.on_doorbell)
    else:
        _LOGGER.warning("Bticino: SIP listener not available, doorbell sensor inactive")


class BticinoDoorbellSensor(BinarySensorEntity):
    """Binary sensor that turns ON for a few seconds when the doorbell rings."""

    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.OCCUPANCY
    _attr_should_poll = False

    def __init__(self, own_params: dict, entry_id: str) -> None:
        self._own_params = own_params
        self._attr_unique_id = f"{entry_id}_doorbell"
        self._attr_name = "Campanello"
        self._attr_is_on = False
        self._reset_cancel = None

    @property
    def device_info(self) -> HaDeviceInfo:
        return HaDeviceInfo(
            identifiers={(DOMAIN, self._own_params["gateway_id"])},
            name="Bticino C300X",
            manufacturer="Bticino / Legrand",
            model="C300X",
        )

    @property
    def icon(self) -> str:
        return "mdi:doorbell"

    @callback
    def on_doorbell(self) -> None:
        """Called from the SIP listener thread when an INVITE arrives."""
        _LOGGER.info("Bticino: doorbell ring detected")
        self._attr_is_on = True
        self.async_write_ha_state()

        if self._reset_cancel is not None:
            self._reset_cancel()

        @callback
        def _reset(_now):
            self._attr_is_on = False
            self.async_write_ha_state()

        self._reset_cancel = async_call_later(self.hass, _DOORBELL_ON_SECONDS, _reset)
