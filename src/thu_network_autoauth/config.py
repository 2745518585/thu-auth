import copy
import os
import tempfile
from ipaddress import AddressValueError, IPv4Address

import questionary
import yaml
from jsonschema import Draft202012Validator, ValidationError
from platformdirs import user_config_dir

from .log import logger

FILE_TAG = "[config]"

config_path = os.path.join(user_config_dir("thu-network-autoauth"), "config.yaml")
logger.info("%s Config path: %s", FILE_TAG, config_path)

config_schema = {
    "type": "object",
    "properties": {
        "account": {"type": "string", "minLength": 1},
        "secret": {
            "type": "object",
            "properties": {"service_name": {"type": "string"}},
            "required": ["service_name"],
        },
        "devices": {"type": "array", "items": {"type": "string"}},
        "config": {
            "type": "object",
            "properties": {
                "requests_timeout": {"type": "integer", "minimum": 1},
                "monitor_interval": {"type": "integer", "minimum": 1},
                "allow_webvpn": {"type": "boolean"},
                "allow_force_attempt": {"type": "boolean"},
                "force_attempt_interval": {"type": "integer", "minimum": 1},
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

_validator = Draft202012Validator(config_schema)
_cached_config = None
_cached_signature = None


class ConfigurationCancelled(Exception):
    """An interactive edit was cancelled; leave the existing file untouched."""


def _ask(question):
    answer = question.ask()
    if answer is None:
        raise ConfigurationCancelled()
    return answer


def valid_ipv4(value: str) -> bool:
    if not value:
        return True
    try:
        IPv4Address(value)
        return True
    except AddressValueError:
        return False


def save_config(config):
    """Replace the file only after a complete, validated write."""
    _validator.validate(config)
    directory = os.path.dirname(config_path)
    os.makedirs(directory, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=directory, suffix=".tmp", delete=False
        ) as output:
            temporary_path = output.name
            yaml.safe_dump(config, output, allow_unicode=True, sort_keys=False)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, config_path)
    finally:
        if temporary_path is not None and os.path.exists(temporary_path):
            os.unlink(temporary_path)


def init_config():
    try:
        _init_config()
    except ConfigurationCancelled:
        logger.info(f"{FILE_TAG} Configuration edit cancelled; file unchanged")


def _init_config():
    try:
        config = load_config(allow_unvalid=True)
    except Exception:
        config = {}

    # Invalid files can still be repaired interactively without crashing defaults.
    for field in ("secret", "config"):
        if not isinstance(config.get(field), dict):
            config[field] = {}
    if not isinstance(config.get("account"), str):
        config["account"] = ""
    if not isinstance(config.get("devices"), list):
        config["devices"] = []
    config["devices"] = [
        device for device in config["devices"] if isinstance(device, str)
    ]

    account = _ask(
        questionary.text(
            "THU Account: ",
            default=config.get("account", ""),
            validate=lambda x: len(x) > 0,
        )
    )

    service_name = _ask(
        questionary.text(
            "Keyring Service Name (for storing password and fingerprint): ",
            default=config.get("secret", {}).get(
                "service_name", "thu-network-autoauth"
            ),
            validate=lambda x: len(x) > 0,
        )
    )

    devices = []
    while True:
        device = _ask(
            questionary.text(
                "Device IPv4 (leave empty to finish): ",
                default=(
                    config.get("devices", [])[len(devices)]
                    if len(config.get("devices", [])) > len(devices)
                    else ""
                ),
                validate=valid_ipv4,
            )
        )
        if not device:
            break
        devices.append(device)

    requests_timeout = _ask(
        questionary.text(
            "Requests Timeout (in seconds): ",
            default=str(config.get("config", {}).get("requests_timeout", 2)),
            validate=lambda x: x.isdigit() and int(x) > 0,
        )
    )

    monitor_interval = _ask(
        questionary.text(
            "Monitor Interval (in seconds): ",
            default=str(config.get("config", {}).get("monitor_interval", 60)),
            validate=lambda x: x.isdigit() and int(x) > 0,
        )
    )

    allow_webvpn = _ask(
        questionary.confirm(
            "Allow using WebVPN for authentication if direct login fails?",
            default=config.get("config", {}).get("allow_webvpn", True),
        )
    )

    allow_force_attempt = _ask(
        questionary.confirm(
            "Allow force attempt to certificate even if the device is not accessible by ping?",
            default=config.get("config", {}).get("allow_force_attempt", False),
        )
    )

    force_attempt_interval = (
        _ask(
            questionary.text(
                "Force Attempt Interval (in seconds): ",
                default=str(
                    config.get("config", {}).get("force_attempt_interval", 600)
                ),
                validate=lambda x: x.isdigit() and int(x) > 0,
            )
        )
        if allow_force_attempt
        else str(config.get("config", {}).get("force_attempt_interval", 600))
    )

    try:
        # Keep extension fields at every level when updating known options.
        config = copy.deepcopy(config)
        config.update(account=account, devices=devices)
        if not isinstance(config.get("secret"), dict):
            config["secret"] = {}
        config["secret"]["service_name"] = service_name
        if isinstance(config.get("password"), dict):
            config["password"]["service_name"] = service_name
        if not isinstance(config.get("config"), dict):
            config["config"] = {}
        config["config"].update(
            {
                "requests_timeout": int(requests_timeout),
                "monitor_interval": int(monitor_interval),
                "allow_webvpn": allow_webvpn,
                "allow_force_attempt": allow_force_attempt,
                "force_attempt_interval": int(force_attempt_interval),
            }
        )

        _validator.validate(config)
    except (ValueError, ValidationError):
        logger.error(f"{FILE_TAG} Configuration validation error")
        return

    save_config(config)


def load_config(allow_unvalid=False):
    global _cached_config, _cached_signature
    try:
        info = os.stat(config_path)
    except FileNotFoundError:
        raise Exception(
            f"{FILE_TAG} Config file not found. Please set it using '-c' or '--config' option."
        ) from None
    signature = (
        config_path,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_size,
        info.st_ino,
    )
    if signature == _cached_signature and _cached_config is not None:
        return copy.deepcopy(_cached_config)
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    if isinstance(config, dict) and "secret" not in config and "password" in config:
        config["secret"] = copy.deepcopy(config["password"])

    try:
        _validator.validate(config)
    except ValidationError as error:
        if allow_unvalid:
            logger.warning(f"{FILE_TAG} Config file is invalid")
            return config if isinstance(config, dict) else {}
        else:
            raise ValueError(
                f"{FILE_TAG} Configuration validation error; please reconfigure using '-c' or '--config' option"
            ) from error

    _cached_config = copy.deepcopy(config)
    _cached_signature = signature
    return config


def get_timeout():
    config = load_config()
    return config["config"]["requests_timeout"]
