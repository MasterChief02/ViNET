from credentials import TWITTER_ACCESS_TOKEN, TWITTER_ACCESS_SECRET, TWITTER_API_KEY, TWITTER_API_SECRET
import requests
import random
import string
from master import main_loop_decorator
from timeit import default_timer as timer
from time import mktime
from datetime import datetime
import requests
import threading
import logging
import tweepy


logging.basicConfig(level=logging.INFO,
                    format="%(message)s",
                    handlers=[logging.FileHandler(f"logs/{mktime(datetime.now().timetuple())}-twitter.log")])

# set logger name
logger = logging.getLogger(__name__)

logger.info("num_chars, time_taken")


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


@main_loop_decorator(iterations=10)
def send_tweet(message: str):
    """Send a tweet"""
    client = tweepy.Client(
        consumer_key=TWITTER_API_KEY, consumer_secret=TWITTER_API_SECRET,
        access_token=TWITTER_ACCESS_TOKEN, access_token_secret=TWITTER_ACCESS_SECRET
    )

    start = timer()
    response = client.create_tweet(
        text=message
    )
    end = timer()
    logger.info(f"{len(message)}, {end-start}")


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
    ("280", generate_random_message(512))
    ]

if __name__ == "__main__":
    for label, message in list_of_telegram_messages:
        send_tweet(message=message)

