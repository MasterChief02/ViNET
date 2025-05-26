import requests
import random
from string import ascii_letters, digits
import argparse
from master import main_loop_decorator
from timeit import default_timer as timer
from time import sleep 
from os import getenv
from datetime import datetime
import requests
import threading
import logging
import subprocess

def check_env_variable(variable):
    if not variable:
        raise ValueError(f"Environment variable {variable} is not set.")

# Load environment variables
TELEGRAM_ACCESS_TOKEN = getenv("TELEGRAM_ACCESS_TOKEN")
TELEGRAM_CHAT_ID = getenv("TELEGRAM_CHAT_ID")

check_env_variable(TELEGRAM_ACCESS_TOKEN)
check_env_variable(TELEGRAM_CHAT_ID)


@main_loop_decorator(iterations=4)
def send_telegram(message: str):
    """Send a message to the telegram channel"""
    url = f"https://api.telegram.org/bot{TELEGRAM_ACCESS_TOKEN}/sendMessage?chat_id={TELEGRAM_CHAT_ID}&text={message}"
    start = timer()
    try:
        response = requests.get(url).json()
        end = timer()
        logger.info(f"{len(message)}, {response['ok']}, {end-start}")
    except Exception as e:
        print(e)

def generate_random_message(length: int) -> str:
    characters = ascii_letters + digits
    return ''.join(random.choice(characters) for i in range(length))


list_of_telegram_messages = [
    ("2", generate_random_message(2)),
    ("4", generate_random_message(4)),
    ("8", generate_random_message(8)),
    ("16", generate_random_message(16)),
    ("32", generate_random_message(32)),
    ("64", generate_random_message(64)),
    ("128", generate_random_message(128)),
    ("256", generate_random_message(256)),
    ("512", generate_random_message(512)),
    ("1024", generate_random_message(1024)),
    ("2048", generate_random_message(2048)),
    ("4096", generate_random_message(4096))
    ]

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Send messages to Telegram channel")
    arg_parser.add_argument("--isp", type=str, default="isp", help="ISP name to be used in the log file name")
    args = arg_parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(message)s",
                        handlers=[logging.FileHandler(f"new_logs/{datetime.now().isoformat()}-telegram-{args.isp}.log")])

    logger = logging.getLogger(__name__)
    logger.info("num_chars, success, time_taken")

    for label, message in list_of_telegram_messages:
        send_telegram(message=message)

