"""Protocol constants for the Bticino C300X library."""

# Cloud portal
PORTAL_BASE_URL = "https://www.myhomeweb.com"
PRJ_NAME = "C3X"
APP_VERSION = f"legacy-1.17.3"

# REST endpoints
API_SIGN_IN = "/eliot/users/sign_in"
API_PLANTS = "/eliot/plants"
API_GW_LIST = "/eliot/plants/{plant_id}/gateway/"
API_GW_INFO = "/eliot/plants/{plant_id}/gateway/{gw_id}"
API_GW_CONF = "/eliot/plants/{plant_id}/gateway/{gw_id}/conf"
API_SIP_USER = "/eliot/sip/users/plants/{plant_id}/gateway/{gw_id}"

# HTTP headers
HEADER_AUTH_TOKEN = "auth_token"
HEADER_PRJ_NAME = "prj_name"
HEADER_NEED_TOKEN = "need_token"
HEADER_MAC_ADDRESS = "mac_address"

# Plant config ZIP password (from decompiled app K2/h.java)
CONF_ZIP_PASSWORD = b"mhpG_123!"

# OWN local protocol
OWN_DEFAULT_PORT = 20000
OWN_ACK = "*#*1##"
OWN_NACK = "*#*0##"

# DTMF door commands (OWN WHO=8)
DTMF_OPEN_STD = "*8*19"    # CID 10060 / 3008
DTMF_CLOSE_STD = "*8*20"
DTMF_OPEN_ALT = "*8*21"    # CID 2009
DTMF_CLOSE_ALT = "*8*22"

# CID groups
CID_STANDARD = {10060, 3008}
CID_ALT = {2009}
CID_CAMERA = {10061}
