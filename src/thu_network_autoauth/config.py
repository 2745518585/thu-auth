import os
import yaml
import questionary
from platformdirs import user_config_dir
from jsonschema import validate
from .log import logger

config_path = os.path.join(user_config_dir("thu-network-autoauth"), "config.yaml")
logger.info("Config path: %s", config_path)

config_schema = {
    "type": "object",
    "properties": {
        "account": {"type": "string"},
        "password": {
            "type": "object",
            "properties": {"service_name": {"type": "string"}},
            "required": ["service_name"],
        },
        "devices": {"type": "array", "items": {"type": "string"}},
        "monitor": {
            "type": "object",
            "properties": {"check_interval": {"type": "integer"}},
            "required": ["check_interval"],
        },
    },
    "required": ["account", "password", "devices", "monitor"],
}


def init_config():
    account = questionary.text("THU Account: ", validate=lambda x: len(x) > 0).ask()

    service_name = questionary.text(
        "Keyring Service Name (for storing password): ",
        default="thu-network-autoauth",
        validate=lambda x: len(x) > 0,
    ).ask()

    devices = []
    while True:
        device = questionary.text(
            "Device IPv4 (leave empty to finish): ",
            validate=lambda x: len(x) == 0
            or (
                len(x.split(".")) == 4
                and all(len(part) > 0 and 0 <= int(part) < 256 for part in x.split("."))
            ),
        ).ask()
        if not device:
            break
        devices.append(device)

    check_interval = questionary.text(
        "Check Interval (in seconds, default 60): ",
        default="60",
        validate=lambda x: x.isdigit() and int(x) > 0,
    ).ask()

    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    try:
        config = {
            "account": account,
            "password": {"service_name": service_name},
            "devices": devices,
            "monitor": {"check_interval": int(check_interval)},
        }

        validate(config, config_schema)
    except Exception:
        logger.error(f"Configuration validation error")
        return

    open(config_path, "w", encoding="utf-8").write(
        yaml.dump(config, allow_unicode=True)
    )


def load_config():
    if not os.path.exists(config_path):
        raise Exception(
            "Config file not found. Please set it using '-c' or '--config' option."
        )
    else:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

    try:
        validate(config, config_schema)
    except Exception:
        raise Exception(
            f"Configuration validation error, pleace reconfigure using '-c' or '--config' option"
        )

    return config
