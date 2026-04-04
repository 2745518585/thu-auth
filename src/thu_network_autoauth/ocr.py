import requests
import ddddocr
import re
from .log import logger

_ocr = ddddocr.DdddOcr(show_ad=False)


def run_ocr(img_url: str, retries: int = 3, timeout: float = 5.0) -> str:

    for attempt in range(retries):
        try:
            # 下载图片
            resp = requests.get(img_url, timeout=timeout)
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
            logger.warning(f"Error downloading captcha image: {e}")
            # 网络问题 → 重试
            continue
        except Exception as e:
            logger.warning(f"Error occurred while recognizing captcha: {e}")
            # OCR 或其他异常
            continue

    logger.error("Failed to recognize captcha after maximum retries")
    raise Exception(
        "Error occurred while recognizing captcha: Failed to recognize captcha after maximum retries"
    )
