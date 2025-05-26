# 1. Phone restart 
# 2. iptable rules
# 3. start middle
# 4. start core
# 5. start call
# 6. sleep
# 7. start test
# 8. stop test
# 9. stop call
# 10. end core
# 11. end middle
# 12. Repeat from 1

import subprocess
import re
import functools
from time import sleep
from enum import Enum
from datetime import datetime

class DeviceID(Enum):
    VINET_1 = "REDACTED_SERIAL_VINET_1"
    SERVER_1 = "REDACTED_SERIAL_SERVER_1"

    VINET_2 = "REDACTED_SERIAL_VINET_2"
    SERVER_2 = "REDACTED_SERIAL_SERVER_2"

    VINET_3 = "REDACTED_SERIAL_VINET_3"
    SERVER_3 = "REDACTED_SERIAL_SERVER_3"


class PhoneNumber(Enum):
    JIO_CALLER = "REDACTED_JIO_CALLER"
    JIO_CALLEE = "REDACTED_JIO_CALLEE"

    AIRTEL_1 = "REDACTED_AIRTEL_1"
    AIRTEL_CALLEE = "REDACTED_AIRTEL_CALLEE"

    VI_CALLER = "REDACTED_VI_CALLER"
    VI_CALLEE = "REDACTED_VI_CALLEE"


class Logger ():
    log_file = open("text.log", "a")

    @staticmethod
    def colorized(text, color):
        colors = {
            "red": "\033[91m",
            "green": "\033[92m",
            "yellow": "\033[93m",
            "blue": "\033[94m",
            "magenta": "\033[95m",
            "cyan": "\033[96m",
            "white": "\033[97m",
            "reset": "\033[0m"
        }
        return f"{colors[color]}{text}{colors['reset']}"


    @staticmethod
    def log(text, color="white"):
        time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        text = f"{time}: {text}"
        print(Logger.colorized(text, color))
        Logger.log_file.write(text + "\n")
        Logger.log_file.flush()


class Device:
    def __init__ (self,
                    mode,
                    adb_device_name,
                    ) -> None:
        self.mode = mode
        self.adb_device_name = adb_device_name
        self.rmnet_interface = ""
        self.rmnet_ipv6 = ""
        self.hotspot_ip = ""
        self.pcap_pid = ""

        if (self.mode == 0):
            self.name = "client"
        else:
            self.name = "server"

    def get_ifaces(self):
        self.rmnet_interface = self.get_interface()
        self.rmnet_ipv6 = self.get_rmnet_ipv6().strip()



    def setup (self):
        Logger.log (f"Initiating setup for {self.name}", "yellow")

        # Turn on wifi hotspot. Note these are device specific coordinates. 
        # Will require adjustment for different devices.
        self.run_command("input touchscreen swipe 930 880 930 50", sleep_time=5)
        self.run_command("am start -n com.android.settings/.TetherSettings", sleep_time=1)  # Go to tethering settings
        self.run_command("input keyevent KEYCODE_DPAD_DOWN", sleep_time=1) # select wifi hotspot
        self.run_command("input keyevent KEYCODE_ENTER", sleep_time=1) # go to wifi hotspot settings
        self.run_command("input keyevent KEYCODE_ENTER", sleep_time=1) # turn on wifi hotspot

        Logger.log ("Turned on wifi hotspot", "green")

        sleep(5)
        self.get_ifaces()
        if self.mode == 0:
            self.hotspot_ip = self.get_wlan0_ip()
            Logger.log(f"hotspot ip_Addr: {self.hotspot_ip}")

        Logger.log(f"IP address: {self.rmnet_ipv6}")
        Logger.log(f"Interface: {self.rmnet_interface}")
    
    def take_pcap(self, task: str, path: str, carrier: str, timeout_seconds: int = 0, root_path: str = "/data/local/tmp/pcaps/",) -> None:
        self.stop_pcap()

        time_str = datetime.now().isoformat()
        file_name = f"{self.name}-{time_str}-{carrier}-{task}.pcap"
        full_path = f"{root_path + path}/{file_name}"

        cmd = f"tcpdump -i {self.rmnet_interface} -w {full_path}"

        Logger.log("mkdir -p " + root_path + path)
        self.run_command("mkdir -p " + root_path + path)

        if timeout_seconds:
            cmd = f"timeout {timeout_seconds} " + cmd

        Logger.log(f"{cmd} & echo $!", "yellow")

        pid = self.check_output(f"{cmd} & echo $!").strip()
        self.pcap_pid = pid

        Logger.log(f"Started tcpdump with pid {pid} and file name {file_name}", "green")

    def stop_pcap(self) -> None:
        if hasattr(self, "pcap_pid"):
            self.run_command(f"kill -9 {self.pcap_pid}")
            Logger.log(f"Stopped tcpdump with pid {self.pcap_pid}", "green")
            del self.pcap_pid

    def set_ipv6_rules(self):
        self.run_command(f"ip6tables -w -t mangle -A INPUT -i {self.rmnet_interface} -p UDP -j NFQUEUE --queue-num 6")
        self.run_command(f"ip6tables -w -t mangle -A OUTPUT -o {self.rmnet_interface} -p UDP -j NFQUEUE --queue-num 5")

    def set_ipv4_rules(self):
        if self.mode == 0:
            self.run_command(f"iptables -w -A OUTPUT -p icmp -s {self.hotspot_ip} -j DROP")
        else:
            self.run_command("iptables -w -t nat -A POSTROUTING -o wlan0 -j MASQUERADE")
            self.run_command("iptables -w -A OUTPUT -o wlan0 -p icmp --icmp-type 3 -j REJECT")

    def setup_core(self) -> None:
        command = f'export PATH="$PATH:/data/data/com.termux/files/usr/bin/"' # export termux path
        command += f"; cd /data/local/tmp/; ./core {self.rmnet_ipv6} &"
        Logger.log(self.run_command(command))
        Logger.log("core ran succesfully", "green")

    def setup_middle(self, ip_addr: str) -> None:
        command = f'export PATH="$PATH:/data/data/com.termux/files/usr/bin/"'
        command += f"; cd /data/local/tmp/"
        if self.mode == 0:
            command += f"; ./router 0 {ip_addr}"
        else:
            command += f"; ./router 1 {ip_addr} 192.168.1.1"
        command += " &"
        Logger.log(self.run_command(command))
        Logger.log("middle ran succesfully", "green")


    def get_interface (self):
        for i in range (1,5):
            result = self.check_output(f"ifconfig rmnet_data{i}")
            if (result.count ("inet6") == 2):
                return f"rmnet_data{i}"
        
        raise Exception("No rmnet_data interface found with two inet6 addresses")


    def get_rmnet_ipv6 (self):
        pattern = r'inet6 addr: (.*?)/64'
        command = f"ifconfig {self.rmnet_interface}"
        result = self.check_output(command)
        matches = re.findall(pattern, result)
        if (len (matches[0]) > len (matches[1])):
            return matches[0]
        else:
            return matches[1]

    def place_call(self, number:str):
        Logger.log(f"Placing call to {number}")
        self.run_command(f"am start -a android.intent.action.CALL -d tel:{number}, --ei android.telecom.extra.START_CALL_WITH_VIDEO_STATE 3")
        self.run_command(f"input keyevent KEYCODE_MUTE")


    def accept_call(self):
        self.run_command("input keyevent KEYCODE_CALL")
        Logger.log("Call accepted", "green")
        self.run_command("input keyevent KEYCODE_MUTE")

    def end_call(self):
        self.run_command("input keyevent KEYCODE_ENDCALL")

    def restart(self):
        subprocess.run(f"adb -s {self.adb_device_name} reboot", shell=True)
        Logger.log(f"Waiting to boot up {self.name}", "yellow")

    def is_up(self):
        subprocess.run(f"adb -s {self.adb_device_name} wait-for-device shell 'while [[ -z $(getprop sys.boot_completed) ]]; do sleep 1; done;'", shell=True)
        Logger.log(f"{self.name} Device booted succesfully", "green")

    def get_wlan0_ip(self):
        pattern = r'inet\s+([0-9.]+)'
        result = self.check_output("ip -f inet addr show wlan0")
        matches = re.findall(pattern, result)
        return matches[0]

    def get_first_3_octets(self) -> str:
        return self.hotspot_ip[:self.hotspot_ip.rfind(".")]

    def check_output(self, command:str, sleep_time:float = 0) -> str:
        final_command = f"adb -s {self.adb_device_name} shell \" su -c \'{command}\' \" &"
        if sleep_time > 0:
            sleep(sleep_time)
        return subprocess.check_output(final_command, shell=True, text=True)

    def run_command(self, command:str, sleep_time:float = 0) -> None:
        subprocess.run(f"adb -s {self.adb_device_name} shell \" su -c \'{command}\' \" &", shell=True)
        if (sleep_time > 0):
            sleep(sleep_time)

    def exit(self):
        self.run_command("pkill -9 core", sleep_time=0.5)
        self.run_command("pkill -9 router")


def main_loop_decorator(iterations:int = 10, last_octate:int = 249):
    """Decorator to run any function under vinet environment
    Things to change in the decorator:
        Iterations: Number of iterations to run the function
    
    Things to change in master:
        Device IDs
        Phone numbers
        Last octate: Last octate of the IP address to be used for the device

    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            vinet = Device(0, DeviceID.VINET_1.value)
            server = Device(1, DeviceID.SERVER_1.value)

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


                for i in range(iterations):
                    func.iteration = i + 1
                    subnet = vinet.get_first_3_octets()
                    vinet.setup_middle(subnet + "." + str(last_octate) ) # last octet is always same for the device
                    server.setup_middle(subnet + "." + str(last_octate))
                    sleep(5)
                    vinet.setup_core()
                    server.setup_core()
                    sleep(5)
                    
                    vinet.place_call(PhoneNumber.AIRTEL_CALLEE.value)
                    sleep(15)
                    server.accept_call()

                    # sleep for 5 seconds
                    sleep(5)


                    # call the function
                    func(*args, **kwargs)
                    
                    # end the call
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
        
            
        return wrapper

    return decorator 

@main_loop_decorator(iterations=10)
def do_nothing():
    while True:
        sleep(1)

if __name__ == "__main__":
    do_nothing()
