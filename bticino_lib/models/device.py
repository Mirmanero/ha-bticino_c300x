"""Data models for the Bticino C300X integration."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PlantInfo:
    plant_id: str
    name: str


@dataclass
class GatewayInfo:
    gateway_id: str
    mac_address: str
    plant_id: str
    local_ip: str = ""


@dataclass
class DeviceInfo:
    """An activatable device parsed from the gateway configuration ZIP.

    cid:  class id  (10060=door, 3008=gate/relay, 2009=alt relay)
    name: user-visible label from archive.xml (e.g. "Serratura", "apre cancello")
    addr: OWN bus address — the {unit} in *8*19*{unit}##
    dev:  OWN device index
    """
    cid: int
    name: str
    addr: str
    dev: str

    def to_dict(self) -> dict:
        return {"cid": self.cid, "name": self.name, "addr": self.addr, "dev": self.dev}

    @classmethod
    def from_dict(cls, data: dict) -> "DeviceInfo":
        return cls(
            cid=int(data["cid"]),
            name=str(data["name"]),
            addr=str(data["addr"]),
            dev=str(data["dev"]),
        )
