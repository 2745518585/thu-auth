from urllib.parse import urljoin
from bs4 import BeautifulSoup
from typing import List
import requests
import base64

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from .config import load_config
from .ocr import run_ocr, CaptchaRecognitionError
from .secret import get_password
from .session import get_session
from .webvpn import get_available_location
from .log import logger

FILE_TAG = "[usereg_api]"

DEFAULT_LOCATION = "https://usereg.tsinghua.edu.cn/"


def check_login(session: requests.Session) -> bool:
    url = urljoin(get_available_location(DEFAULT_LOCATION), "home")
    resp = session.get(url, allow_redirects=False)
    if resp.status_code == 401:
        return False
    resp.raise_for_status()
    if resp.status_code == 200:
        return (
            BeautifulSoup(resp.text, "html.parser").select_one(".query-online")
            is not None
        )
    else:
        return False


def login() -> None:
    config = load_config()
    session = get_session()

    def rsa_encrypt(password: str, public_key_str: str):
        key = RSA.importKey(public_key_str)
        cipher = PKCS1_v1_5.new(key)
        encrypted = cipher.encrypt(password.encode("utf-8"))
        return base64.b64encode(encrypted).decode()

    if check_login(session):
        return

    logger.info(f"{FILE_TAG} Start logging in to thu network self-service system")

    base_url = urljoin(get_available_location(DEFAULT_LOCATION), "login")

    # Keep key, captcha and CSRF from the same page; refresh unreadable captchas.
    for attempt in range(3):
        resp = session.get(base_url)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        public = soup.select_one("#public")
        captcha = soup.select_one("#loginform-verifycode-image")
        csrf_param = soup.select_one('meta[name="csrf-param"]')
        csrf_token = soup.select_one('meta[name="csrf-token"]')
        if not public or not public.get("value"):
            if soup.select_one(".query-online") is not None:
                return
            raise RuntimeError(f"{FILE_TAG} Public key not found on login page")
        if not captcha or not captcha.get("src"):
            raise RuntimeError(f"{FILE_TAG} Captcha image URL not found on login page")
        if (
            not csrf_param
            or not csrf_param.get("content")
            or not csrf_token
            or not csrf_token.get("content")
        ):
            raise RuntimeError(f"{FILE_TAG} CSRF parameter or token not found")
        public_key = str(public["value"])
        captcha_url = urljoin(resp.url, str(captcha["src"]))
        try:
            verify_code = run_ocr(captcha_url, retries=1)
        except CaptchaRecognitionError:
            if attempt == 2:
                raise
            logger.warning(f"{FILE_TAG} Refreshing login page after unreadable captcha")
            continue

        # 加密密码
        username = config["account"]
        password = get_password()
        if not password:
            raise Exception(f"{FILE_TAG} Password not available from keyring")
        encrypted_pwd = rsa_encrypt(password, public_key)

        csrf_param = str(csrf_param["content"])
        csrf_token = str(csrf_token["content"])

        # 构造表单
        data = {
            "LoginForm[username]": username,
            "LoginForm[password]": encrypted_pwd,
            "LoginForm[verifyCode]": verify_code,
            csrf_param: csrf_token,
        }

        # 发送登录请求
        resp = session.post(base_url, data=data)
        resp.raise_for_status()

        if check_login(session):
            logger.info(f"{FILE_TAG} Login successful")
            return

        raise Exception(f"{FILE_TAG} Login failed")

    raise CaptchaRecognitionError(f"{FILE_TAG} Captcha attempts exhausted")


def get_online_ips() -> List[str]:
    login()
    session = get_session()
    url = urljoin(get_available_location(DEFAULT_LOCATION), "home")

    logger.info(f"{FILE_TAG} Getting online IPv4 address list")

    # 请求页面
    resp = session.get(url)
    resp.raise_for_status()

    # 解析 HTML
    soup = BeautifulSoup(resp.text, "html.parser")

    # 找到 .query-online 区块
    container = soup.select_one(".query-online")
    if not container:
        raise Exception(f"{FILE_TAG} Online info section (.query-online) not found")

    # 提取 IP 列（data-col-seq="1"）
    ips = [td.get_text(strip=True) for td in container.select('td[data-col-seq="1"]')]

    logger.info(f"{FILE_TAG} Online IPv4 address list: {ips}")
    return ips


def send_certification(ip: str) -> bool:
    login()
    session = get_session()
    url = urljoin(get_available_location(DEFAULT_LOCATION), "certification")

    logger.info(f"{FILE_TAG} Sending certification request, IP: {ip}")

    # 获取页面，提取 csrf
    resp = session.get(url)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    csrf_param = soup.select_one('meta[name="csrf-param"]')
    csrf_token = soup.select_one('meta[name="csrf-token"]')
    if not csrf_param or not csrf_token:
        raise Exception(f"{FILE_TAG} CSRF parameter or token not found")
    csrf_param = str(csrf_param["content"])
    csrf_token = str(csrf_token["content"])

    # 密码
    password = get_password()
    if not password:
        raise Exception(f"{FILE_TAG} Password not available from keyring")

    # 构造表单
    data = {
        "CertificationForm[ip]": ip,
        "CertificationForm[password]": password,
        "CertificationForm[type]": "out",
        csrf_param: csrf_token,
    }

    # 发送 POST 请求
    resp = session.post(url, data=data)
    resp.raise_for_status()

    # 检查是否有错误信息
    soup = BeautifulSoup(resp.text, "html.parser")
    error_div = soup.select_one("div.alert-danger")
    if error_div:
        # 提取错误文本
        error_text = error_div.get_text(strip=True).lstrip("×x ")
        logger.warning(
            f"{FILE_TAG} Certification request failed, IP: {ip}, Error: {error_text}"
        )
        return False

    if ip not in get_online_ips():
        logger.warning(
            f"{FILE_TAG} Certification not confirmed in online list, IP: {ip}"
        )
        return False
    logger.info(f"{FILE_TAG} Certification request successful, IP: {ip}")
    return True
