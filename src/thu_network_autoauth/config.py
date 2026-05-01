import os
import yaml
import questionary
from platformdirs import user_config_dir
from jsonschema import validate
from .log import logger

FILE_TAG = "[config]"

config_path = os.path.join(user_config_dir("thu-network-autoauth"), "config.yaml")
logger.info("%s Config path: %s", FILE_TAG, config_path)

config_schema = {
    "type": "object",
    "properties": {
        "account": {"type": "string"},
        "secret": {
            "type": "object",
            "properties": {"service_name": {"type": "string"}},
            "required": ["service_name"],
        },
        "devices": {"type": "array", "items": {"type": "string"}},
        "config": {
            "type": "object",
            "properties": {
                "requests_timeout": {"type": "integer"},
                "monitor_interval": {"type": "integer"},
                "allow_webvpn": {"type": "boolean"},
                "allow_force_attempt": {"type": "boolean"},
                "force_attempt_interval": {"type": "integer"},
            },
            "required": [
                "requests_timeout",
                "monitor_interval",
                "allow_webvpn",
                "allow_force_attempt",
                "force_attempt_interval",
            ],
        },
    },
    "required": ["account", "secret", "devices", "config"],
}


def init_config():
    try:
        config = load_config(allow_unvalid=True)
    except Exception:
        config = {}

    account = questionary.text(
        "THU Account: ",
        default=config.get("account", ""),
        validate=lambda x: len(x) > 0,
    ).ask()

    service_name = questionary.text(
        "Keyring Service Name (for storing password and fingerprint): ",
        default=config.get("secret", {}).get("service_name", "thu-network-autoauth"),
        validate=lambda x: len(x) > 0,
    ).ask()

    devices = []
    while True:
        device = questionary.text(
            "Device IPv4 (leave empty to finish): ",
            default=(
                config.get("devices", [])[len(devices)]
                if len(config.get("devices", [])) > len(devices)
                else ""
            ),
            validate=lambda x: len(x) == 0
            or (
                len(x.split(".")) == 4
                and all(len(part) > 0 and 0 <= int(part) < 256 for part in x.split("."))
            ),
        ).ask()
        if not device:
            break
        devices.append(device)

    requests_timeout = questionary.text(
        "Requests Timeout (in seconds): ",
        default=str(config.get("config", {}).get("requests_timeout", 2)),
        validate=lambda x: x.isdigit() and int(x) > 0,
    ).ask()

    monitor_interval = questionary.text(
        "Monitor Interval (in seconds): ",
        default=str(config.get("config", {}).get("monitor_interval", 60)),
        validate=lambda x: x.isdigit() and int(x) > 0,
    ).ask()

    allow_webvpn = questionary.confirm(
        "Allow using WebVPN for authentication if direct login fails?",
        default=config.get("config", {}).get("allow_webvpn", True),
    ).ask()

    allow_force_attempt = questionary.confirm(
        "Allow force attempt to certificate even if the device is not accessible by ping?",
        default=config.get("config", {}).get("allow_force_attempt", False),
    ).ask()

    force_attempt_interval = (
        questionary.text(
            "Force Attempt Interval (in seconds): ",
            default=str(config.get("config", {}).get("force_attempt_interval", 600)),
            validate=lambda x: x.isdigit() and int(x) > 0,
        ).ask()
        if allow_force_attempt
        else "600"
    )

    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    try:
        config = {
            "account": account,
            "secret": {"service_name": service_name},
            "devices": devices,
            "config": {
                "requests_timeout": int(requests_timeout),
                "monitor_interval": int(monitor_interval),
                "allow_webvpn": allow_webvpn,
                "allow_force_attempt": allow_force_attempt,
                "force_attempt_interval": int(force_attempt_interval),
            },
        }

        validate(config, config_schema)
    except Exception:
        logger.error(f"{FILE_TAG} Configuration validation error")
        return

    open(config_path, "w", encoding="utf-8").write(
        yaml.dump(config, allow_unicode=True)
    )


def load_config(allow_unvalid=False):
    if not os.path.exists(config_path):
        raise Exception(
            f"{FILE_TAG} Config file not found. Please set it using '-c' or '--config' option."
        )
    else:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

    try:
        validate(config, config_schema)
    except Exception:
        if allow_unvalid:
            logger.warning(f"{FILE_TAG} Config file is invalid")
        else:
            raise Exception(
                f"{FILE_TAG} Configuration validation error; please reconfigure using '-c' or '--config' option"
            )

    return config


def get_timeout():
    config = load_config()
    return config["config"]["requests_timeout"]
