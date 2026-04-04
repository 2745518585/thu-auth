import time
import argparse
from .log import logger
from .monitor import check_ip_available
from . import config as Config
from . import passwd
from . import usereg_api

parser = argparse.ArgumentParser()
parser.add_argument(
    "--password",
    "-p",
    action="store_true",
    help="Set or update the password in keyring",
)
parser.add_argument(
    "--config",
    "-c",
    action="store_true",
    help="Initialize or update the configuration file",
)
args = parser.parse_args()


def main():
    if args.config:
        Config.init_config()
        return
    if args.password:
        passwd.set_password()
        return

    logger.info("Starting thu-auth...")

    try:
        passwd.get_password()
        config = Config.load_config()

    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return

    logger.info("Account: {}".format(config["account"]))
    logger.info("Monitoring IPs: {}".format(", ".join(config["devices"])))
    logger.info(
        "Check interval: {} seconds".format(config["monitor"]["check_interval"])
    )

    while True:

        try:

            ips = usereg_api.get_online_ips()
            logger.info(f"Currently online IPs: {', '.join(ips) if ips else 'None'}")

            for ip in config["devices"]:

                if not check_ip_available(ip):
                    logger.info(f"IP {ip} is not available, skipping...")
                    continue

                if ip in ips:
                    logger.info(f"IP {ip} is already online, skipping...")
                    continue

                logger.info(f"IP {ip} is not online, sending certification request...")
                success = usereg_api.send_certification(ip)
                if success:
                    logger.info(f"Certification request for IP {ip} sent successfully")
                else:
                    logger.error(f"Failed to send certification request for IP {ip}")

        except Exception as e:
            logger.error(f"Skip a turn for unexpected error occurred: {e}")

        time.sleep(config["monitor"]["check_interval"])


if __name__ == "__main__":
    main()
