# 1. Phone restart (?)
# 2. if phone restart => iptable rules
# 3. start middle
# 4. start core
# 5. start call
# 6. sleep
# 7. start test
# 8. stop test
# 9. stop call
# 10. end core
# 11. end middle
# 12. goto 3 if not restart phone, else goto 1

import subprocess
import socket
import re
from termcolor import cprint

from time import sleep
from datetime import datetime

    
class Logger ():
    log_file = open ("text.log", "a")

    @staticmethod
    def log (text, color="white"):
        time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        text = f"{time}: {text}"
        cprint(text, color)
        Logger.log_file.write(text + "\n")
        Logger.log_file.flush ()


class Device:
    def __init__ (self,
                    mode,
                    adb_device_name,
                    port) -> None:
        self.mode = mode
        self.adb_device_name = adb_device_name
        self.port = port

        self.control_socket = socket.socket()

        if (self.mode == 0):
            self.name = "client"
        else:
            self.name = "server"

    def get_ifaces(self):
        self.rmnet_interface = self.get_interface()        
        self.rmnet_ipv6 = self.get_rmnet_ipv6().strip()



    def setup (self):
        Logger.log (f"Initiating setup for {self.name}", "yellow")

        # Turn on wifi hotspot        
        # self.run_command("input keyevent 26")
        # sleep(1)
        # self.run_command("input touchscreen swipe 930 880 930 180")
        # sleep(1)
        self.run_command("am start -n com.android.settings/.TetherSettings")  # Go to tethering settings
        sleep(0.5)
        self.run_command("input keyevent KEYCODE_DPAD_DOWN") # select wifi hotspot
        sleep(0.5)
        self.run_command("input keyevent KEYCODE_ENTER") # go to wifi hotspot settings
        sleep(0.5)
        self.run_command("input keyevent KEYCODE_ENTER") # turn on wifi hotspot

        Logger.log ("Turned on wifi hotspot", "green")
                
        sleep(5)
        self.get_ifaces()
        if self.mode == 0:
            self.hotspot_ip = self.get_wlan0_ip()
            Logger.log(f"hotspot ip_Addr: {self.hotspot_ip}")

        Logger.log(f"IP address: {self.rmnet_ipv6}")
        Logger.log(f"Interface: {self.rmnet_interface}")

    def set_ipv6_rules(self):
        self.run_command(f"ip6tables -t mangle -A INPUT -i {self.rmnet_interface} -p UDP -j NFQUEUE --queue-num 5")
        self.run_command(f"ip6tables -t mangle -A OUTPUT -o {self.rmnet_interface} -p UDP -j NFQUEUE --queue-num 5")

    def set_ipv4_rules(self):
        if self.mode == 0:
            self.run_command(f"iptables -A OUTPUT -p icmp -s {self.hotspot_ip} -j DROP")
        else:
            self.run_command("iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE")
            self.run_command("iptables -A OUTPUT -o wlan0 -p icmp --icmp-type 3 -j REJECT")

    def setup_core(self) -> None:
        command = f'export PATH="$PATH:/data/data/com.termux/files/usr/bin/"' # export termux path
        command += f"; cd /data/local/tmp/; ./core {self.rmnet_ipv6} &" 
        Logger.log(self.run_command(command))
        Logger.log("core ran succesfully", "green")

    def setup_middle(self) -> None:
        command = f'export PATH="$PATH:/data/data/com.termux/files/usr/bin/"'
        command += f"; cd /data/local/tmp/"
        if self.mode == 0:
            command += f"; ./router 0 192.168.40.152" # TODO replace with client ID
        else:
            command += f"; ./router 1 192.168.40.152 192.168.1.1"  # TODO replace with client ID
        command += " &"
        Logger.log(self.run_command(command))
        Logger.log("middle ran succesfully", "green")


    def get_interface (self):
        for i in range (1,5):
            result = self.check_output(f"ifconfig rmnet_data{i}") 
            if (result.count ("inet6") == 2):
                return f"rmnet_data{i}"
            
    
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
        self.run_command(f"am start -a android.intent.action.CALL -d tel:{number}, --ei android.telecom.extra.START_CALL_WITH_VIDEO_STATE 3")

    def accept_call(self):
        self.run_command("input keyevent KEYCODE_CALL")

    def end_call(self):
        self.run_command("input keyevent KEYCODE_ENDCALL")


    def get_wlan0_ip(self):
        pattern = r'inet\s+([0-9.]+)' # galat hai regex. TODO fix it
        # return self.check_output(r"ip -f inet addr show wlan0 | sed -En -e 's/.*inet ([0-9.]+).*/\1/p'")
        result = self.check_output("ip -f inet addr show wlan0")
        matches = re.findall(pattern, result)
        return matches[0]


    def check_output(self, command):
        final_command = f"adb -s {self.adb_device_name} shell \" su -c \'{command}\' \" &"
        return subprocess.check_output(final_command, shell=True, text=True)
        
    def run_command(self, command):
        subprocess.run(f"adb -s {self.adb_device_name} shell \" su -c \'{command}\' \" &", shell=True)

    def exit(self):
        self.run_command("pkill -9 router")
        self.run_command("pkill -9 core")

if __name__ == "__main__":
    vinet = Device(0, "ZD2222DX7R", 5000)
    server = Device(1, "ZF6527C3LT", 5001)
    server.get_ifaces()
    try:
        vinet.setup()
        vinet.set_ipv4_rules()
        vinet.set_ipv6_rules()

        server.set_ipv4_rules()
        server.set_ipv6_rules()
        
        vinet.setup_middle()
        server.setup_middle()
        sleep(5)
        vinet.setup_core()
        server.setup_core()
        sleep(5)

        vinet.place_call("8810521496")
        sleep(5)
        server.accept_call()
        
        while True:
            continue

    except KeyboardInterrupt:
        server.end_call()
        vinet.exit()
        server.exit()

    