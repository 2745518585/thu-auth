import time
import argparse
from importlib.metadata import version, PackageNotFoundError
from .log import logger
from .monitor import check_ip_available
from . import config as Config
from . import secret, usereg_api
from .session import reset_session
from .webvpn import reset_location_cache

FILE_TAG = "[main]"


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        "-c",
        action="store_true",
        help="Initialize or update the configuration file",
    )
    parser.add_argument(
        "--password",
        "-p",
        action="store_true",
        help="Set or update the password in keyring",
    )
    parser.add_argument(
        "--fingerprint",
        "-f",
        action="store_true",
        help="Set or update the device fingerprint in keyring",
    )
    try:
        package_version = version("thu-network-autoauth")
    except PackageNotFoundError:
        package_version = "development"
    parser.add_argument(
        "--version", "-v", action="version", version=f"%(prog)s {package_version}"
    )
    return parser


def monitor_cycle(config, last_force_attempt_time):
    ips = usereg_api.get_online_ips()
    logger.info(f"{FILE_TAG} Currently online IPs: {', '.join(ips) if ips else 'None'}")
    now = time.monotonic()
    force_attempt = config["config"]["allow_force_attempt"] and (
        last_force_attempt_time is None
        or now - last_force_attempt_time >= config["config"]["force_attempt_interval"]
    )
    if force_attempt:
        logger.info(f"{FILE_TAG} Force attempt interval reached")
        last_force_attempt_time = now

    failed = False
    for ip in config["devices"]:
        try:
            if ip in ips:
                logger.info(f"{FILE_TAG} IP {ip} is already online, skipping...")
                continue
            if not force_attempt and not check_ip_available(ip):
                logger.info(f"{FILE_TAG} IP {ip} is not available, skipping...")
                continue
            logger.info(
                f"{FILE_TAG} IP {ip} is not online, sending certification request..."
            )
            if usereg_api.send_certification(ip):
                logger.info(
                    f"{FILE_TAG} Certification request for IP {ip} sent successfully"
                )
            else:
                logger.warning(
                    f"{FILE_TAG} Certification not confirmed for IP {ip}; will retry in a later cycle"
                )
        except Exception:
            failed = True
            logger.exception(
                f"{FILE_TAG} Error handling IP {ip}; continuing with other devices"
            )
    return last_force_attempt_time, failed


def run_service():
    last_force_attempt_time = None
    previous_config = None
    failures = 0
    while True:
        interval = 60
        failed = False
        try:
            # Configuration and credential repairs take effect without restarting.
            config = Config.load_config()
            interval = config["config"]["monitor_interval"]
            secret.get_password()
            if config["config"]["allow_webvpn"]:
                secret.get_fingerprint()
            if config != previous_config:
                reset_location_cache()
                reset_session()
                last_force_attempt_time = None
                logger.info(
                    f"{FILE_TAG} Monitoring {len(config['devices'])} devices; interval: {interval} seconds"
                )
                previous_config = config
            last_force_attempt_time, failed = monitor_cycle(
                config, last_force_attempt_time
            )
        except Exception:
            failed = True
            logger.exception(
                f"{FILE_TAG} Monitoring cycle failed; service will retry automatically"
            )

        if failed:
            failures += 1
            reset_location_cache()
            try:
                reset_session()
            except Exception:
                logger.exception(f"{FILE_TAG} Error closing failed session")
            delay = min(interval * (2 ** min(failures - 1, 9)), max(interval, 300))
            logger.warning(
                f"{FILE_TAG} Consecutive failures: {failures}; retrying in {delay} seconds"
            )
        else:
            if failures:
                logger.info(
                    f"{FILE_TAG} Monitoring recovered after {failures} failed cycles"
                )
            failures = 0
            delay = interval
        time.sleep(delay)


def main(argv=None):
    args = create_parser().parse_args(argv)
    try:
        if args.config:
            Config.init_config()
        elif args.password:
            secret.set_password()
        elif args.fingerprint:
            secret.set_fingerprint()
        else:
            logger.info(f"{FILE_TAG} Starting thu-auth...")
            run_service()
    except KeyboardInterrupt:
        logger.info(f"{FILE_TAG} Stopped by user")
    finally:
        try:
            reset_session()
        except Exception:
            logger.exception(f"{FILE_TAG} Error closing session during shutdown")


if __name__ == "__main__":
    main()
