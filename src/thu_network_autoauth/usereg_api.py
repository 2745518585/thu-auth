from urllib.parse import urljoin
from bs4 import BeautifulSoup
from typing import List
import requests
import base64
import re

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from .config import load_config
from .ocr import run_ocr
from .passwd import get_password
from .log import logger


def check_login(session: requests.Session) -> bool:
    url = "https://usereg.tsinghua.edu.cn/home"
    resp = session.get(url, allow_redirects=False)
    if resp.status_code == 200:
        return True
    else:
        return False


def login() -> requests.Session:

    config = load_config()

    global session
    session = requests.Session()

    def get_public_key(session, base_url):
        resp = session.get(base_url)
        resp.raise_for_status()
        m = re.search(
            r'id="public" value="(-----BEGIN PUBLIC KEY-----.+?-----END PUBLIC KEY-----)"',
            resp.text,
            re.S,
        )
        if not m:
            raise Exception("未找到公钥")
        return m.group(1)

    def get_captcha_url(session, base_url):
        resp = session.get(base_url)
        resp.raise_for_status()
        m = re.search(r'<img id="loginform-verifycode-image" src="([^"]+)"', resp.text)
        if not m:
            raise Exception("未找到验证码图片 URL")
        return urljoin(base_url, m.group(1))

    def rsa_encrypt(password, public_key_str):
        key = RSA.importKey(public_key_str)
        cipher = PKCS1_v1_5.new(key)
        encrypted = cipher.encrypt(password.encode("utf-8"))
        return base64.b64encode(encrypted).decode()

    if check_login(session):
        return session

    logger.info("Start logging in to thu network self-service system")

    base_url = "https://usereg.tsinghua.edu.cn/login"

    # 获取公钥
    public_key = get_public_key(session, base_url)

    # 获取验证码图片URL
    captcha_url = get_captcha_url(session, base_url)

    # 识别验证码
    verify_code = run_ocr(captcha_url)

    # 加密密码
    username = config["account"]
    password = get_password()
    if not password:
        raise Exception("未找到密码")
    encrypted_pwd = rsa_encrypt(password, public_key)

    # 获取csrf参数和token
    resp = session.get(base_url)
    resp.raise_for_status()
    csrf_param = re.search(r'<meta name="csrf-param" content="([^"]+)"', resp.text)
    csrf_token = re.search(r'<meta name="csrf-token" content="([^"]+)"', resp.text)
    if not csrf_param or not csrf_token:
        raise Exception("未找到 CSRF 参数或令牌")
    csrf_param = csrf_param.group(1)
    csrf_token = csrf_token.group(1)

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
        logger.info("Login successful")
        return session

    raise Exception("Login failed")


def get_online_ips() -> List[str]:
    url = "https://usereg.tsinghua.edu.cn/home"
    session = login()

    logger.info("Getting online IPv4 address list")

    # 请求页面
    resp = session.get(url)
    resp.raise_for_status()

    # 解析 HTML
    soup = BeautifulSoup(resp.text, "html.parser")

    # 找到 .query-online 区块
    container = soup.select_one(".query-online")
    if not container:
        raise Exception("未找到在线信息区域 (.query-online)")

    # 提取 IP 列（data-col-seq="1"）
    ips = [td.get_text(strip=True) for td in container.select('td[data-col-seq="1"]')]

    logger.info(f"Online IPv4 address list: {ips}")
    return ips


def send_certification(ip: str) -> bool:
    session = login()
    url = "https://usereg.tsinghua.edu.cn/certification"

    logger.info(f"Sending certification request, IP: {ip}")

    # 获取页面，提取 csrf
    resp = session.get(url)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    csrf_param = soup.find("meta", attrs={"name": "csrf-param"})
    csrf_token = soup.find("meta", attrs={"name": "csrf-token"})
    if not csrf_param or not csrf_token:
        raise Exception("未找到 CSRF 参数或令牌")
    csrf_param = str(csrf_param["content"])
    csrf_token = str(csrf_token["content"])

    # 密码
    password = get_password()
    if not password:
        raise Exception("未找到密码")

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
    error_div = soup.find("div", class_="alert-danger")
    if error_div:
        # 提取错误文本
        error_text = error_div.get_text(strip=True).replace("x", "", 1).strip()
        raise Exception(error_text)

    logger.info(f"Certification request successful, IP: {ip}")
    return True
