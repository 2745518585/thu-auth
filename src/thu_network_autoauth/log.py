import logging
import os
from logging.handlers import RotatingFileHandler
from platformdirs import user_log_dir

LOG_DIR = user_log_dir("thu-network-autoauth")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, "thu-network-autoauth.log")

# 配置日志，最大 5MB，保留 3 个历史文件
handler = RotatingFileHandler(
    LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
)
formatter = logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s")
handler.setFormatter(formatter)

logger = logging.getLogger("thu-network-autoauth")
logger.setLevel(logging.INFO)
logger.addHandler(handler)

# 可选：同时输出到控制台
console = logging.StreamHandler()
console.setFormatter(formatter)
logger.addHandler(console)

logger.info("Log path: %s", LOG_PATH)
