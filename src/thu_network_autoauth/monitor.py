import ping3

from .config import load_config
from .log import logger

FILE_TAG = "[monitor]"


def check_ip_available(ip: str) -> bool:
    try:
        delay = ping3.ping(ip, timeout=load_config()["config"]["requests_timeout"])
        return delay is not None and delay is not False
    except Exception as e:
        logger.error(f"{FILE_TAG} Error checking IP {ip}: {e}")
        return False
