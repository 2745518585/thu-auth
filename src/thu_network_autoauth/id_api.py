import re
import requests

from gmssl import sm2

from .config import load_config
from .passwd import get_password
from .session import get_session
from .log import logger

FILE_TAG = "[id_api]"


def get_public_key(html: str) -> str:
    m = re.search(r'id="sm2publicKey">([^<]+)<', html)
    if not m:
        raise Exception(f"{FILE_TAG} sm2publicKey not found in login page")
    return m.group(1).strip()


def sm2_encrypt(password: str, public_key: str) -> str:
    sm2_crypt = sm2.CryptSM2(
        public_key=public_key,
        private_key="",
        mode=1,
    )

    cipher = sm2_crypt.encrypt(password.encode())
    if not cipher:
        raise Exception(f"{FILE_TAG} SM2 encryption failed")

    cipher_hex = cipher.hex()

    return "04" + cipher_hex


def check_login(session: requests.Session) -> bool:
    url = "https://id.tsinghua.edu.cn/f/account/settings"
    resp = session.get(url, allow_redirects=False)
    if resp.status_code == 200:
        return True
    else:
        return False


LOGIN_PAGE = "https://id.tsinghua.edu.cn/f/login"
LOGIN_API = "https://id.tsinghua.edu.cn/security_check"


def login(force_relogin: bool = False) -> None:

    config = load_config()
    session = get_session()

    if not force_relogin and check_login(session):
        return

    logger.info(f"{FILE_TAG} Start logging in to thu electronic ID service system")

    # Step 1: 访问登录页（拿 cookie + 公钥）
    resp = session.get(LOGIN_PAGE)
    resp.raise_for_status()

    html = resp.text

    # Step 2: 提取公钥
    public_key = get_public_key(html)

    # Step 3: 加密密码
    encrypted_password = sm2_encrypt(get_password(), public_key)

    # Step 4: 构造 POST 数据
    data = {
        "username": config["account"],
        "password": encrypted_password,
        "fingerPrint": config["environment"]["finger_print"],
        "deviceName": "windows,Edge/148",
        "singleLogin": "on",
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": LOGIN_PAGE,
        "User-Agent": "Mozilla/5.0",
    }

    # Step 5: 发送登录请求
    resp = session.post(LOGIN_API, data=data, headers=headers)
    resp.raise_for_status()

    if check_login(session):
        logger.info(f"{FILE_TAG} Login successful")
        return

    raise Exception(f"{FILE_TAG} Login failed")


CHECK_SINGLE_API = "https://id.tsinghua.edu.cn/do/off/ui/auth/login/checkSingle"
FINGER_PRINT_3_API = "https://id.tsinghua.edu.cn/b/doubleAuth/personal/getFinger3"


def get_finger_print_3(session: requests.Session) -> str:
    resp = session.get(FINGER_PRINT_3_API)
    resp.raise_for_status()
    data = resp.json()

    if data.get("result") != "success":
        login(force_relogin=True)
        resp = session.get(FINGER_PRINT_3_API)
        resp.raise_for_status()
        data = resp.json()
        if data.get("result") != "success":
            raise Exception(f"{FILE_TAG} Failed to get finger print 3 after re-login: {data}")

    return data.get("object")


def auth_page(url: str):

    login()
    config = load_config()
    session = get_session()

    resp = session.get(url)
    if resp.url == url:
        return

    logger.info(f"{FILE_TAG} Authenticating page {url} through ID service")

    data = {
        "i_rememberme": "on",
        "fingerPrint": config["environment"]["finger_print"],
        "fingerGenPrint": get_finger_print_3(session),
    }

    resp = session.post(CHECK_SINGLE_API, data=data)
    resp.raise_for_status()

    match = re.search(r'window\.location\.replace\("([^"]+)"\)', resp.text)

    if not match:
        raise Exception(f"{FILE_TAG} Redirect URL not found in response")
    
    redirect_url = match.group(1)

    resp = session.get(redirect_url)
    resp.raise_for_status()

    if resp.url == url:
        logger.info(f"{FILE_TAG} Successfully authenticated page {url}")
        return
    
    raise Exception(f"{FILE_TAG} Authentication failed for {url}; current URL: {resp.url}")
