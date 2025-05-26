from time import sleep
from os import getenv
import random
import argparse
import string
from timeit import default_timer as timer
from datetime import datetime
import logging
import tweepy
from master import main_loop_decorator


# Load environment variables
TWITTER_ACCESS_TOKEN = getenv("TWITTER_ACCESS_TOKEN")
TWITTER_ACCESS_SECRET = getenv("TWITTER_ACCESS_SECRET")
TWITTER_API_KEY = getenv("TWITTER_API_KEY")
TWITTER_API_SECRET = getenv("TWITTER_API_SECRET")

def check_env_variable(variable):
    if not variable:
        raise ValueError(f"Environment variable {variable} is not set.")

check_env_variable(TWITTER_ACCESS_TOKEN)
check_env_variable(TWITTER_ACCESS_SECRET)
check_env_variable(TWITTER_API_KEY)
check_env_variable(TWITTER_API_SECRET)



@main_loop_decorator(iterations=10)
def send_tweet(len: int):
    """Send a tweet"""
    client = tweepy.Client(
        consumer_key=TWITTER_API_KEY, consumer_secret=TWITTER_API_SECRET,
        access_token=TWITTER_ACCESS_TOKEN, access_token_secret=TWITTER_ACCESS_SECRET
    )

    message = generate_random_message(len)
    failed = False
    start = timer()
    try:
        response = client.create_tweet(
            text=message
        )
    except Exception as e:
        failed = True
        print(e)
    end = timer()
    if not failed:
        logger.info(f"{len}, {end-start}")
    else:
        logger.info(f"{len}, 60.0")
    sleep(1)


def generate_random_message(length: int) -> str:
    """
    Return a random message with `length` words
    """
    valid_chars = string.ascii_letters + string.digits
    return ''.join(random.choice(valid_chars) for i in range(length))

tweets_lens = [
    50,
    100,
    150,
    200,
    250,
    280
]

tweets_lens.reverse()



if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description="Send tweets of different lengths")
    argparser.add_argument("--isp", type=str, default="isp", help="ISP name to be used in the log file name")
    args = argparser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(message)s",
                        handlers=[logging.FileHandler(f"logs/{datetime.now().isoformat()}-twitter-{args.isp}.log")])

    logger = logging.getLogger(__name__)
    logger.info("message_len, time_taken")

    for len in tweets_lens:
        send_tweet(len)

