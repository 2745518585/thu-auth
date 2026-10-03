import time
import requests
from urllib.parse import urlparse

from Crypto.Cipher import AES

from .session import get_session
from .config import load_config
from .log import logger
from . import id_api

FILE_TAG = "[webvpn]"


def get_wrdvpn_keys(session: requests.Session):
    url = "https://webvpn.tsinghua.edu.cn/user/info"

    resp = session.get(url)
    resp.raise_for_status()

    data = resp.json()
    if not isinstance(data, dict):
        raise RuntimeError(f"{FILE_TAG} Invalid WebVPN user info response")

    key = data.get("wrdvpnKey")
    iv = data.get("wrdvpnIV")

    if not isinstance(key, str) or not isinstance(iv, str):
        raise RuntimeError(
            f"{FILE_TAG} Missing or invalid WebVPN encryption parameters"
        )

    key_bytes, iv_bytes = key.encode("utf-8"), iv.encode("utf-8")
    if len(key_bytes) not in {16, 24, 32} or len(iv_bytes) != 16:
        raise RuntimeError(f"{FILE_TAG} Invalid WebVPN encryption parameter lengths")

    return key_bytes, iv_bytes


def wengine_encode(url: str) -> str:
    key, iv = get_wrdvpn_keys(get_session())

    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    encrypted = cipher.encrypt(url.encode("utf-8"))
    return iv.hex() + encrypted.hex()


def get_webvpn_url(target_location: str) -> str:
    id_api.auth_page("https://webvpn.tsinghua.edu.cn/")

    encoded_location = wengine_encode(target_location)
    logger.info(
        f"{FILE_TAG} Encoded Location {target_location} for webvpn: {encoded_location}"
    )

    return f"https://webvpn.tsinghua.edu.cn/https/{encoded_location}/"


last_location: dict[str, str] = {}
last_check: dict[str, float] = {}


def reset_location_cache():
    last_location.clear()
    last_check.clear()


def get_available_location(url: str) -> str:
    if not url.endswith("/"):
        url += "/"
    location = urlparse(url).netloc

    global last_check, last_location

    session = get_session()
    config = load_config()["config"]

    if not config["allow_webvpn"]:
        last_location[location] = url
        last_check.pop(location, None)
        return url

    if (
        location in last_check
        and time.monotonic() - last_check[location] < config["monitor_interval"]
    ):
        return last_location[location]

    logger.info(f"{FILE_TAG} Checking if default URL is accessible")

    try:
        resp = session.get(url, timeout=5)
        resp.raise_for_status()
        selected = url
    except requests.RequestException:
        logger.info(f"{FILE_TAG} Default URL not accessible, trying webvpn")
        selected = get_webvpn_url(location)

    # Cache only successful discovery, so a failed VPN login cannot poison it.
    last_location[location] = selected
    last_check[location] = time.monotonic()
    logger.info(f"{FILE_TAG} Using URL: {selected}")

    return last_location[location]
