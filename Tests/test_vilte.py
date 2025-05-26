from master import Device, DeviceID, PhoneNumber
from time import sleep
from datetime import datetime
from random import randint
import subprocess
import argparse

# take as argument the carrier
def take_pcap(device: Device, label: str, interface: str):
    time_str = datetime.now().isoformat()
    device.run_command(f"timeout 60 tcpdump -i {interface} -w /data/local/tmp/pcaps/vilte/{device.name}-{device.adb_device_name}-{time_str}-{label}-do_nothing.pcap &")

def do_nothing():
    sleep(60)

def main(func):
    # get the carrier name
    args_parser = argparse.ArgumentParser(description="Run the test")
    args_parser.add_argument("--carrier", type=str, help="Carrier name")
    args = args_parser.parse_args()
    carrier = args.carrier
    

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

        for _ in range(5):
            vinet.place_call(PhoneNumber.VI_CALLEE.value)
            sleep(15)

            take_pcap(vinet, carrier, vinet.rmnet_interface)
            take_pcap(server, carrier, server.rmnet_interface)

            server.accept_call()

            sleep(5)

            func()
                
            server.end_call()
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
    main(do_nothing) 
