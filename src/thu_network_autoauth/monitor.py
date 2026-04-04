import ping3
from .log import logger


def check_ip_available(ip: str) -> bool:
    try:
        delay = ping3.ping(ip, timeout=2)
        return delay is not None
    except Exception as e:
        logger.error(f"Error checking IP {ip}: {e}")
        return False
