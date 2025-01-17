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
                    handlers=[logging.FileHandler(f"logs/{mktime(datetime.now().timetuple())}-file_transfer.log")])

# set logger name
logger = logging.getLogger(__name__)

logger.info("file size(bytes), time taken(s), speed(bytes/s)")


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
def file_transfer(url: str):
    """Download the file from the given url and return the total time taken"""
    result = subprocess.run(f"curl -O {url} -m 1000 --connect-timeout 30 -w '%{{size_download}}, %{{time_total}} %{{speed_download}}'", 
                            shell=True,
                            text=True,
                            capture_output=True)
    
    logger.info(result.stdout)




list_of_urls = [
    #("100K", "http://192.168.224.76:8000/100K"),
    #("200K", "http://192.168.224.76:8000/200K"),
    #("300K", "http://192.168.224.76:8000/300K"),
    #("400K", "http://192.168.224.76:8000/400K"),
    #("500K", "http://192.168.224.76:8000/500K"),
    #("600K", "http://192.168.224.76:8000/600K"),
    #("700K", "http://192.168.224.76:8000/700K"),
    #("800K", "http://192.168.224.76:8000/800K"),
    #("900K", "http://192.168.224.76:8000/900K"),
    ("1M", "http://192.168.224.76:8000/1M"),
    ]

if __name__ == "__main__":
    for label, url in list_of_urls:
        file_transfer(url)
