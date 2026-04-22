"""Constants for the Bticino C300X integration."""

# --- Cloud portal ---
PORTAL_BASE_URL = "https://www.myhomeweb.com"
PORTAL_PORT = 443
PRJ_NAME = "C3X"
APP_VERSION_PREFIX = "legacy-"
APP_VERSION = "1.17.3"

# --- SIP servers ---
SIP_REMOTE_SERVER = "sipserver.bs.iotleg.com"
SIP_TLS_PORT = 5061
SIP_DOMAIN_SUFFIX = ".bs.iotleg.com"
SIP_GATEWAY_TARGET = "c300x"           # sip:c300x@{gateway}

# --- Local gateway ---
OWN_DEFAULT_PORT = 20000               # porta del protocollo OWN (da G2/f.java)
OWN_DISCOVERY_PASSWORD_DEFAULT = "12345"  # PswOpen di default (dalla cloud API)
OWN_FRAME_TERMINATOR = "##"
OWN_PROTOCOL_VERSION = "2"

# --- DTMF door commands ---
# CID 10060 / 3008  →  videocitofono standard
DTMF_OPEN_STD = "*8*19"
DTMF_CLOSE_STD = "*8*20"
# CID 2009  →  altro tipo
DTMF_OPEN_ALT = "*8*21"
DTMF_CLOSE_ALT = "*8*22"
# Sensore apertura
DTMF_SENSOR = "*13*35*##"
# Unità default quando non specificata
DEFAULT_UNIT = "4"

# CID grouping
CID_STANDARD = {10060, 3008}
CID_ALT = {2009}

# --- REST API endpoints ---
API_SIGN_IN = "/eliot/users/sign_in"
API_USER = "/eliot/user"
API_PLANTS = "/eliot/plants"
API_PLANT = "/eliot/plants/{plant_id}"
API_GW_LIST = "/eliot/plants/{plant_id}/gateway/"
API_GW_INFO = "/eliot/plants/{plant_id}/gateway/{gw_id}"
API_GW_CONF = "/eliot/plants/{plant_id}/gateway/{gw_id}/conf"
API_SIP_USER = "/eliot/sip/users/plants/{plant_id}/gateway/{gw_id}"
API_TLS = "/eliot/sip/tls/{device_id}"

# --- HTTP headers ---
HEADER_AUTH_TOKEN = "auth_token"
HEADER_PRJ_NAME = "prj_name"
HEADER_CONTENT_TYPE = "Content-Type"
HEADER_NEED_TOKEN = "need_token"
HEADER_MAC_ADDRESS = "mac_address"
CONTENT_TYPE_JSON = "application/json"

# --- Plant config ZIP ---
# Password del file ZIP restituito da /conf (da K2/h.java → S4.b.b())
CONF_ZIP_PASSWORD = b"mhpG_123!"

# --- SIP headers ---
SIP_VERSION = "SIP/2.0"
SIP_TRANSPORT = "TLS"
SIP_EXPIRES = 5184000                  # 60 giorni (come nell'app originale)
SIP_USER_AGENT = f"BticinoC300X/{APP_VERSION}"
