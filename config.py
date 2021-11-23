import binascii
import os

APP_SECRET_KEY = os.environ.get("APP_SECRET_KEY", None)

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

SDM_META_READ_KEY = binascii.unhexlify(os.environ.get("SDM_META_READ_KEY", "00000000000000000000000000000000"))
SDM_FILE_READ_KEY = binascii.unhexlify(os.environ.get("SDM_FILE_READ_KEY", "00000000000000000000000000000000"))

ENC_PICC_DATA_PARAM = os.environ.get("ENC_PICC_DATA_PARAM", "picc_data")
ENC_FILE_DATA_PARAM = os.environ.get("ENC_FILE_DATA_PARAM", "enc")

UID_PARAM = os.environ.get("UID_PARAM", "uid")
CTR_PARAM = os.environ.get("CTR_PARAM", "ctr")

SDMMAC_PARAM = os.environ.get("SDMMAC_PARAM", "cmac")

TAG_SECRET = os.environ.get("TAG_SECRET_KEY", None)
