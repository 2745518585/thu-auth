import keyring
import questionary
from .config import load_config
from .log import logger


def get_password():

    config = load_config()
    password = keyring.get_password(
        config["password"]["service_name"], config["account"]
    )

    if not password:
        raise Exception(
            "Password not found in keyring. Please set it using '-p' or '--password' option."
        )

    return password


def set_password():

    config = load_config()

    logger.info("Updating password...")
    new_password = questionary.password("New Password: ").ask()
    reinput_password = questionary.password("Re-enter New Password: ").ask()

    if new_password != reinput_password:
        logger.error("Passwords do not match.")
        return

    keyring.set_password(
        config["password"]["service_name"], config["account"], new_password
    )
