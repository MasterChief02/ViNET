from master import main_loop_decorator
from time import sleep, mktime
from datetime import datetime
import logging
import argparse
import subprocess


@main_loop_decorator(iterations=15)
def file_transfer(url: str):
    """Download the file from the given url and return the total time taken"""
    result = subprocess.run(f"curl {url} -o /dev/null -m 1000 --connect-timeout 30 -w '%{{size_download}}, %{{time_total}}, %{{speed_download}}' 2>/dev/null", 
                            shell=True,
                            text=True,  
                            capture_output=True)
    
    logger.info(result.stdout)


list_of_urls = [
    ("100K", "http://192.168.224.76/100K"),
    ("200K", "http://192.168.224.76/200K"),
    ("300K", "http://192.168.224.76/300K"),
    ("400K", "http://192.168.224.76/400K"),
    ("500K", "http://192.168.224.76/500K"),
    ("600K", "http://192.168.224.76/600K"),
    ("700K", "http://192.168.224.76/700K"),
    ("800K", "http://192.168.224.76/800K"),
    ("900K", "http://192.168.224.76/900K"),
    ("1M", "http://192.168.224.76/1M"),
    ]

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Send messages to Telegram channel")
    arg_parser.add_argument("--isp", type=str, default="isp", help="ISP name to be used in the log file name")
    args = arg_parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(message)s",
                        handlers=[logging.FileHandler(f"new_logs/{datetime.now().isoformat()}-file_transfer-{args.isp}.log")])

    logger = logging.getLogger(__name__)
    logger.info("file size(bytes), time taken(s), speed(bytes/s)")

    for label, url in list_of_urls:
        file_transfer(url)
