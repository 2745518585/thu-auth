import keyring
import questionary
from .config import load_config
from .log import logger

FILE_TAG = "[secret]"


def get_secret_storage_key(key: str) -> str:
    config = load_config()
    return f"{config['account']}:{key}"


def get_password():
    config = load_config()
    password = keyring.get_password(
        config["secret"]["service_name"], f"{config['account']}:password"
    )

    if not password:
        raise Exception(
            f"{FILE_TAG} Password not found in keyring. Please set it using '-p' or '--password' option."
        )

    return password


def set_password():
    config = load_config()

    logger.info(f"{FILE_TAG} Updating password...")
    new_password = questionary.password("Enter Password: ").ask()
    if not new_password:
        logger.info(f"{FILE_TAG} Password update cancelled; stored password unchanged")
        return
    reinput_password = questionary.password("Re-enter Password: ").ask()

    if new_password != reinput_password:
        logger.error(f"{FILE_TAG} Passwords do not match.")
        return

    keyring.set_password(
        config["secret"]["service_name"],
        f"{config['account']}:password",
        new_password,
    )


def get_fingerprint() -> str:
    config = load_config()
    fingerprint = keyring.get_password(
        config["secret"]["service_name"], f"{config['account']}:fingerprint"
    )

    if not fingerprint:
        raise Exception(
            f"{FILE_TAG} Fingerprint not found in keyring. Please set it using '-f' or '--fingerprint' option."
        )

    return fingerprint


def set_fingerprint():
    config = load_config()

    logger.info(f"{FILE_TAG} Updating Fingerprint ...")
    fingerprint = questionary.text("New value for Fingerprint: ").ask()
    if not fingerprint or not fingerprint.strip():
        logger.info(
            f"{FILE_TAG} Fingerprint update cancelled; stored fingerprint unchanged"
        )
        return

    keyring.set_password(
        config["secret"]["service_name"],
        f"{config['account']}:fingerprint",
        fingerprint,
    )
