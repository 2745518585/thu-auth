import logging
import os
import re
from logging.handlers import RotatingFileHandler
from platformdirs import user_log_dir

FILE_TAG = "[log]"


def redact_sensitive_text(text: str) -> str:
    # Request exceptions include callback URLs with OAuth codes and tokens.
    text = re.sub(r"([?&][\w.%-]+=)([^&\s'\"<>)]*)", r"\1[REDACTED]", text)
    return re.sub(
        r"(?i)(\b(?:password|fingerprint|fingerGenPrint|wrdvpnKey|wrdvpnIV|csrf-token)\b['\"]?\s*[:=]\s*['\"]?)([^'\"\s,}&]+)",
        r"\1[REDACTED]",
        text,
    )


class RedactingFormatter(logging.Formatter):
    def format(self, record):
        return redact_sensitive_text(super().format(record))


class NoExceptionFormatter(RedactingFormatter):
    """控制台用：不打印异常堆栈"""

    def format(self, record):
        record = logging.makeLogRecord(record.__dict__.copy())
        record.exc_info = None
        record.exc_text = None
        return super().format(record)


LOG_DIR = user_log_dir("thu-network-autoauth")
LOG_PATH = os.path.join(LOG_DIR, "thu-network-autoauth.log")

logger = logging.getLogger("thu-network-autoauth")
logger.setLevel(logging.INFO)
logger.propagate = False

# 可选：同时输出到控制台
console = logging.StreamHandler()
console.setFormatter(NoExceptionFormatter("[%(levelname)s] %(message)s"))
logger.addHandler(console)

# A read-only/full log directory must not prevent service startup.
try:
    os.makedirs(LOG_DIR, exist_ok=True)
    handler = RotatingFileHandler(
        LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(
        RedactingFormatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s")
    )
    logger.addHandler(handler)
except OSError as error:
    logger.warning("%s File logging unavailable; using console: %s", FILE_TAG, error)

logger.info("%s Log path: %s", FILE_TAG, LOG_PATH)
