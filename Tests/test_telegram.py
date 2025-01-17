from credentials import TELEGRAM_ACCESS_TOKEN, TELEGRAM_CHAT_ID
import requests
import random
import string
from master import main_loop_decorator
from timeit import default_timer as timer
from time import sleep, mktime
from datetime import datetime
import requests
import threading
import logging
import subprocess


logging.basicConfig(level=logging.INFO,
                    format="%(message)s",
                    handlers=[logging.FileHandler(f"logs/{mktime(datetime.now().timetuple())}-telegram.log")])

# set logger name
logger = logging.getLogger(__name__)

logger.info("num_chars, success, time_taken")


# decorator to calculate the time taken by the function. If the function is taking more than x seconds, exit the program
def timeit(func, time_limit=1000):
    def wrapper(*args, **kwargs):
        stop_flag = threading.Event()
        result = [None]

        def target():
            try:
                result[0] = func(stop_flag, *args, **kwargs)
            except Exception as e:
                print(f"Function terminated: {e}")

        thread = threading.Thread(target=target)
        start = timer()
        thread.start()
        thread.join(timeout=time_limit)
        end = timer()
        elapsed = end - start

        if thread.is_alive():
            print(f"Time limit exceeded: {elapsed}")
            stop_flag.set()
            thread.join()  # Ensure the thread has finished
            raise SystemExit
        return elapsed
    return wrapper


@main_loop_decorator(iterations=20)
def send_telegram(message: str):
    """Send a message to the telegram channel"""
    url = f"https://api.telegram.org/bot{TELEGRAM_ACCESS_TOKEN}/sendMessage?chat_id={TELEGRAM_CHAT_ID}&text={message}"
    start = timer()
    response = requests.get(url).json()
    end = timer()
    logger.info(f"{len(message)}, {response['ok']}, {end-start}")

def generate_random_message(length: int) -> str:
    characters = string.ascii_letters + string.digits
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
    for label, message in list_of_telegram_messages:
        send_telegram(message=message)

