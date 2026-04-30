import time
import argparse
from importlib.metadata import version
from .log import logger
from .monitor import check_ip_available
from . import config as Config
from . import secret
from . import usereg_api

FILE_TAG = "[main]"

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
parser.add_argument(
    "--version",
    "-v",
    action="version",
    version=f"%(prog)s {version('thu-network-autoauth')}",
)
args = parser.parse_args()


def main():
    if args.config:
        Config.init_config()
        return
    if args.password:
        secret.set_password()
        return
    if args.fingerprint:
        secret.set_fingerprint()
        return

    logger.info(f"{FILE_TAG} Starting thu-auth...")

    try:
        config = Config.load_config()
        secret.get_password()
        if config["config"]["allow_webvpn"]:
            secret.get_fingerprint()

    except Exception as e:
        logger.error(f"{FILE_TAG} Error loading configuration: {e}")
        return

    logger.info(f"{FILE_TAG} Account: {config['account']}")
    logger.info(f"{FILE_TAG} Monitoring IPs: {', '.join(config['devices'])}")
    logger.info(
        f"{FILE_TAG} Check interval: {config['monitor']['check_interval']} seconds"
    )

    while True:

        try:

            ips = usereg_api.get_online_ips()
            logger.info(
                f"{FILE_TAG} Currently online IPs: {', '.join(ips) if ips else 'None'}"
            )

            for ip in config["devices"]:

                if not check_ip_available(ip):
                    logger.info(f"{FILE_TAG} IP {ip} is not available, skipping...")
                    continue

                if ip in ips:
                    logger.info(f"{FILE_TAG} IP {ip} is already online, skipping...")
                    continue

                logger.info(
                    f"{FILE_TAG} IP {ip} is not online, sending certification request..."
                )
                success = usereg_api.send_certification(ip)
                if success:
                    logger.info(
                        f"{FILE_TAG} Certification request for IP {ip} sent successfully"
                    )
                else:
                    logger.error(
                        f"{FILE_TAG} Failed to send certification request for IP {ip}"
                    )

        except Exception as e:
            logger.exception(
                f"{FILE_TAG} Skipping this cycle due to unexpected error: {e}"
            )

        time.sleep(config["monitor"]["check_interval"])


if __name__ == "__main__":
    main()
