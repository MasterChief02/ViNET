import logging
import subprocess
import argparse
from datetime import datetime
from timeit import default_timer as timer
from master import main_loop_decorator




@main_loop_decorator(iterations=10)
def search_google():
    query = "https://www.google.com/search?q=How+to+effectively+use+mindfulness+meditation+techniques+to+reduce+stress+and+anxiety%2C+improve+focus%2C+enhance+productivity%2C+and+maintain+mental+well-being+during+challenging+work+or+study+periods+while+managing+distractions%3F"
    start = timer()
    try:
        subprocess.run(f'lynx -dump -accept_all_cookies -read_timeout=20 {query} > /dev/null',
                        shell=True)
        end = timer()
        logger.info(f"{end-start}")
    except:
        logger.info("-1")

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Send messages to Telegram channel")
    arg_parser.add_argument("--isp", type=str, default="isp", help="ISP name to be used in the log file name")
    args = arg_parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(message)s",
                        handlers=[logging.FileHandler(f"logs/{datetime.now().isoformat()}-gsearch-{args.isp}.log")])

    logger = logging.getLogger(__name__)
    logger.info("time_taken")

    search_google()

