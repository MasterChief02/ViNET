from master import Device, DeviceID, PhoneNumber
from time import sleep, time
from datetime import datetime
from random import randint
import subprocess
import argparse


def take_pcap(device: Device, label: str, interface: str):
    time_str = datetime.now().isoformat()
    device.run_command(f"timeout 60 tcpdump -i {interface} -w /data/local/tmp/pcaps/vinet/{device.name}-{device.adb_device_name}-{time_str}-{label}-vinet.pcap udp &")

def do_nothing():
    sleep(600)

def do_random_file_transfers(url: str):
    start_time = time()

    while (time() - start_time < 60):
        subprocess.run(f"curl -O {url} -m 50 --connect-timeout 30 2>/dev/null 1>/dev/null", shell=True)
        sleep(5)    

def main(func, label):
    # get the carrier name
    carriers = ["airtel", "jio", "vi"]

    arg_parser = argparse.ArgumentParser(description="Run the test")
    arg_parser.add_argument("--carrier", type=str, help="Carrier name", choices=carriers, default="airtel")    
    arg_parser.add_argument("--url", type=str, default="http://192.168.224.76/100K", help="URL to fetch for test")

    args = arg_parser.parse_args()
    carrier = args.carrier

    if carrier == "airtel":
        number = PhoneNumber.AIRTEL_CALLEE.value
    elif carrier == "jio":
        number = PhoneNumber.JIO_CALLEE.value
    elif carrier == "vi":
        number = PhoneNumber.VI_CALLEE.value
    else:
        raise ValueError("Invalid carrier name. Choose from 'airtel', 'jio', or 'vi'.")


    vinet = Device(0, DeviceID.VINET_1.value)
    server = Device(1, DeviceID.SERVER_1.value)

    vinet.run_command("pkill tcpdump")
    server.run_command("pkill tcpdump")


    server.restart()
    server.is_up()
    vinet.restart()
    vinet.is_up()
    sleep(5)
    server.get_ifaces()
    try:
        vinet.setup()
        vinet.set_ipv4_rules()
        vinet.set_ipv6_rules()

        server.set_ipv4_rules()
        server.set_ipv6_rules()

        subnet = vinet.get_first_3_octets()
        for _ in range(5):
            vinet.setup_middle(subnet + ".249") # EDIT: Change this for your network
            server.setup_middle(subnet + ".249")
            sleep(5)
            vinet.setup_core()
            server.setup_core()
            sleep(5)


            # start the call
            vinet.place_call(PhoneNumber.VI_CALLEE.value)
            sleep(10)
            
            take_pcap(vinet, carrier, vinet.rmnet_interface)
            take_pcap(server, carrier, server.rmnet_interface)

            server.accept_call()


            sleep(5)
            func(args.url)


            # end the call
            server.end_call()
            vinet.exit()
            server.exit()
            sleep(5)

        vinet.exit()
        server.exit()
        sleep(5)


        vinet.exit()
        server.exit()

    finally:
        server.end_call()
        vinet.exit()
        server.exit()

        # pkill the tcpdump process
        vinet.run_command("pkill tcpdump")
        server.run_command("pkill tcpdump")

if __name__ == "__main__":
    main(do_random_file_transfers, "do_nothing")
