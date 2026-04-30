import time
import requests
from urllib.parse import urlparse

from Crypto.Cipher import AES

from .session import get_session
from .config import load_config
from .log import logger
from . import id_api


def get_wrdvpn_keys(session: requests.Session):
    url = "https://webvpn.tsinghua.edu.cn/user/info"

    resp = session.get(url)
    resp.raise_for_status()

    data = resp.json()

    key = data.get("wrdvpnKey")
    iv = data.get("wrdvpnIV")

    if not key or not iv:
        raise Exception(f"未获取到 wrdvpnKey / wrdvpnIV: {data}")

    return key.encode("utf-8"), iv.encode("utf-8")


def wengine_encode(url: str) -> str:
    key, iv = get_wrdvpn_keys(get_session())

    logger.info(f"Obtained wrdvpnKey and wrdvpnIV: {key}, {iv}")

    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    encrypted = cipher.encrypt(url.encode("utf-8"))
    return iv.hex() + encrypted.hex()


def get_webvpn_url(target_location: str) -> str:

    id_api.login()
    id_api.auth_page("https://webvpn.tsinghua.edu.cn/")

    encoded_location = wengine_encode(target_location)
    logger.info(f"Encoded Location {target_location} for webvpn: {encoded_location}")

    return f"https://webvpn.tsinghua.edu.cn/https/{encoded_location}"


last_location: dict[str, str] = {}
last_check: dict[str, float] = {}


def get_available_location(location: str) -> str:
    location = urlparse(location).netloc
    
    global last_check, last_location

    if last_check.get(location) is None:
        last_check[location] = 0
    if last_location.get(location) is None:
        last_location[location] = location

    session = get_session()

    if time.time() - last_check[location] < load_config()["monitor"]["check_interval"]:
        return last_location[location]

    last_check[location] = time.time()

    logger.info("Checking if default URL is accessible")

    try:
        resp = session.get(location, timeout=5)
        last_location[location] = location
        logger.info(f"Using default URL: {last_location[location]}")
    except Exception as e:
        logger.info(f"Default URL not accessible, trying webvpn")
        last_location[location] = get_webvpn_url(location)
        logger.info(f"Using webvpn URL: {last_location[location]}")

    return last_location[location]
