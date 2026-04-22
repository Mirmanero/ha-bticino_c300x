"""Data models for the Bticino C300X integration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AuthToken:
    """Token returned by the sign-in endpoint."""
    token: str


@dataclass
class UserInfo:
    """Basic user info from /eliot/user."""
    user_id: int
    username: str
    email: str


@dataclass
class GatewayInfo:
    """Gateway (C300X device) info."""
    gateway_id: str          # e.g. "ABCDEF012345"  (MAC-derived ID used as SIP domain)
    mac_address: str         # hardware MAC
    plant_id: str
    local_ip: Optional[str] = None    # filled during local discovery
    own_port: int = 20000             # port for OWN local protocol


@dataclass
class PlantInfo:
    """Installation/plant info."""
    plant_id: str
    name: str
    gateways: list[GatewayInfo] = field(default_factory=list)


@dataclass
class SipCredentials:
    """SIP account credentials returned by the API."""
    username: str           # e.g. "user@ABCDEF012345.bs.iotleg.com"
    password: str
    domain: str             # e.g. "ABCDEF012345.bs.iotleg.com"
    gateway_id: str
    device_name: str = ""

    @property
    def sip_uri(self) -> str:
        u = self.username if "@" in self.username else f"{self.username}@{self.domain}"
        return f"sip:{u}"


@dataclass
class TlsCertificates:
    """TLS client certificates returned by the API (Base64 encoded)."""
    ca_cert_pem: str        # Root CA certificate
    client_cert_pem: str    # Client certificate
    client_key_pem: str     # Client private key


@dataclass
class DeviceInfo:
    """Attuatore/dispositivo ricavato dal file di configurazione del gateway.

    Corrisponde a una voce nella sezione 'Attivazioni' dell'app ufficiale.
    Il comando OWN da inviare dipende dal CID:
      CID 10060 / 3008 → *8*19*{addr}## / *8*20*{addr}##
      CID 2009         → *8*21*{addr}## / *8*22*{addr}##
      CID 10050        → vivavoce secondario (nessun comando porta)
    """
    cid: int
    name: str
    addr: str   # indirizzo sul bus OWN (es. "4", "5")
    dev: str    # numero dispositivo OWN (es. "1", "2")


@dataclass
class GatewayConfig:
    """Complete local configuration needed to operate without cloud."""
    plant: PlantInfo
    gateway: GatewayInfo
    sip_credentials: SipCredentials
    tls_certificates: Optional[TlsCertificates] = None
    own_password: str = "12345"
    devices: list[DeviceInfo] = field(default_factory=list)
