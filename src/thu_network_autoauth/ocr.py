import requests
import ddddocr
import re

from .session import get_session
from .log import logger

_ocr = ddddocr.DdddOcr(show_ad=False)

FILE_TAG = "[ocr]"


def run_ocr(img_url: str, retries: int = 3, timeout: float = 5.0) -> str:

    session = get_session()

    for attempt in range(retries):
        try:
            # 下载图片
            resp = session.get(img_url, timeout=timeout)
            resp.raise_for_status()

            # OCR 识别
            result = _ocr.classification(resp.content)

            # 类型检查
            if not isinstance(result, str):
                continue

            result = result.strip()

            # 校验是否为 4 位数字
            if re.fullmatch(r"\d{4}", result):
                return result

        except requests.RequestException as e:
            logger.warning(f"{FILE_TAG} Error downloading captcha image {img_url}: {e}")
            # 网络问题 → 重试
            continue
        except Exception as e:
            logger.warning(f"{FILE_TAG} Error occurred while recognizing captcha {img_url}: {e}")
            # OCR 或其他异常
            continue

    logger.error(f"{FILE_TAG} Failed to recognize captcha {img_url} after maximum retries")
    raise Exception(
        f"{FILE_TAG} Error occurred while recognizing captcha: Failed to recognize captcha after maximum retries"
    )
