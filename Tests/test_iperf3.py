from master import main_loop_decorator
from datetime import datetime
import json
import logging
import subprocess
import argparse


@main_loop_decorator(iterations=15)
def iper3_test():
    result = subprocess.run("iperf3 -c 192.168.224.76 --json --connect-timeout 30000" , 
                            shell=True,
                            text=True,  
                            capture_output=True)
    
    if result.returncode == 0:
        result = json.loads(result.stdout)

        if result.get("error", None) != None:
            return

        file_name = f"logs/json/{datetime.now().isoformat()}-airtel-iperf3.json"
        with open(file_name, "w") as f:
            json.dump(result, f, indent=2)

        logger.info(result["end"]["sum_received"]["bits_per_second"])


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Get size and time taken to fetch websites")
    arg_parser.add_argument("--isp", type=str, default="isp", help="ISP name to be used in the log file name")

    args = arg_parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(message)s",
                        handlers=[logging.FileHandler(f"logs/{datetime.now().isoformat()}-iper3-{args.isp}.log")])

    logger = logging.getLogger(__name__)
    logger.info("speed(bits/s)")

    iper3_test()

