from master import main_loop_decorator
from time import sleep, mktime
from datetime import datetime
import subprocess
import logging
import os
import argparse

# check if the script is run with root privileges
def check_root():
    if os.geteuid() != 0:
        raise PermissionError("This script must be run as root.")


def add_host_entry(url):
    """
    This function adds an entry to the /etc/hosts file for the given URL.
    We were having lots of issues related to DNS resolution, so we decided to turn off global DNS resolution 
    and manually get the IP address of the URL and add it to the /etc/hosts file.
    We are using DNS over simple http to get the IP address of the URL, but DoH can be used for enhanced security.
    """
    url_name = url.replace("https://", "").replace("http://", "").replace("/", "")
    ip_addr = subprocess.run(f"dig +tcp @8.8.8.8 {url_name} A +short", shell=True, capture_output=True)
    ip_addr = ip_addr.stdout.decode().strip().split("\n")[-1]

    if "no servers could be reached" in ip_addr:
        print("DNS resolution failed")
        return

    print(f"IP Address: {ip_addr}")
    with open("/etc/hosts", "a") as f:
        f.write(f"{ip_addr} {url_name}\n")


@main_loop_decorator(iterations=5)
def fetch_website(url: str):
    add_host_entry(url)
    result = subprocess.run(f"curl --tlsv1.2 {url} -o ~/index.html -m 180 --keepalive-time 180 --connect-timeout 30 -w '%{{url}}, %{{size_download}}, %{{time_total}}, %{{speed_download}}'", 
                            shell=True,
                            text=True,
                            capture_output=True)
    
    logger.info(result.stdout)

if __name__ == "__main__":
    type_of_sites = ["paper_custom", "tranco_custom", "user_custom"]

    arg_parser = argparse.ArgumentParser(description="Get size and time taken to fetch websites")
    arg_parser.add_argument("--isp", type=str, default="isp", help="ISP name to be used in the log file name")
    arg_parser.add_argument("--sites", type=str, default="sites/custom_sites.txt", help="File containing the list of sites to test")
    arg_parser.add_argument("--type", choices=type_of_sites, default="paper_custom", help="Type of sites to test")
    args = arg_parser.parse_args()

    if args.type == "paper_custom":
        with open("sites/paper_custom.txt", "r") as f:
            sites = f.read().split()
    elif args.type == "tranco_custom":
        with open("sites/tranco_custom.txt", "r") as f:
            sites = f.read().split()
    else:
        with open(args.sites, "r") as f:
            sites = f.read().split()

    logging.basicConfig(level=logging.INFO,
                        format="%(message)s",
                        handlers=[logging.FileHandler(f"logs/{datetime.now().isoformat()}-website-tranco-{args.isp}.log")])

    logger = logging.getLogger(__name__)
    logger.info("url, size(bytes), time taken(s), speed(bytes/s)")

    for site in sites:
        subprocess.run("sudo cp /tmp/hosts /etc", shell=True)
        fetch_website(site)
