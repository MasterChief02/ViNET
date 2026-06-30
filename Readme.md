NOTE - Datasets and results generated for security and performace evaluation are not included in this repository. These datasets and result logs can be shared if required.

## Repository Structure
- `Core` - Contains the implementation of the `Tunnel` application. There are many flavours. We have used `EncryptNonBlock.cpp` in our testing.
- `Middle` - Contains the implementatio of the `Relay` application. There are some variations for different applications. We have used `Router.cpp` in our testing.
- `Common` - Contains some utility code used by both `Tunnel` and `Relay` application e.g. Logger.
- `Plots` - Contains the code for plotting the graphs for the obtained results from the experiments done with ViNET.
- `Analysis` - Contains the scripts for security analysis and feature extraction.
- `Tests` - Contains the scripts for automated testing framework for the ViNET.
- `Makefile` - Script to compile ViNET's code.

## Instructions to run ViNET

1. Get rooted devices

2. Installing Netfilter queue
    1. Install termux on the device
    2. enable its root-repo and x11-repo
    3. install apt
    4. install libnetfilter-queue and libnetfilter-queue-static
    5. To install any other package: `<pkg install PACKAGE_NAME>`
    6. To search any other package : `<pkg search PACKAGE_NAME>`
  
3. Clone the repo and move the ViNETs code to `/data/local/tmp` of the device.
4. Compile the code using the following commands
     1. `aarch64-linux-android-g++ ViNET/Core/EncryptNonBlock.cpp -o core -lnetfilter_queue -lssl -lcrypto`
     2. `aarch64-linux-android-g++ ViNET/Middle/Router.cpp -o router -lpthread`
     3. Or use the provided `Makefile`.
        
5. Turn on WiFi hotspot for one device you want to setup as Android Client. And connect the ViNET client device (laptop) to it using the WiFi.
6. Turn on the WiFi on the Android Peer and connect it to the internet.
7. Identify the `rmnet_data{n}` interface which is connected to LTE, will have a IPv6 (Turn of the internet on both the devices to easily identify the interface)
8. Add the following `iptable` rules on the Android client
     1. `ip6tables -t mangle -A INPUT -i rmnet_data{n} -p UDP -j NFQUEUE --queue-num 5`
     2. `ip6tables -t mangle -A OUTPUT -o rmnet_data{n} -p UDP -j NFQUEUE --queue-num 6`
     3. If you want to use ping also then add `iptables -A OUTPUT -p icmp -s <CLIENT_DEVICE_WIFI_IP> -j DROP`
9. Add the following `iptable` rules on the Android Peer.
    1. `ip6tables -t mangle -A INPUT -i rmnet_data{n} -p UDP -j NFQUEUE --queue-num 5`
    2. `ip6tables -t mangle -A OUTPUT -o rmnet_data1{n} -p UDP -j NFQUEUE --queue-num 6`
    3. `iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE`
    4. `iptables -A OUTPUT -o wlan0 -p icmp --icmp-type 3 -j REJECT`
  
10. Run `core` using the command `./core <self_ip>`, here self_ip is the IPv6 assigned to the rmnet_data{n} of the device.
11. Run `router`
      1. For Android client run `./router <client_ip>`, here client_ip is the IP of the ViNET client device viz. the laptop.
      2. For Android peer run `./router <client_ip> 192.168.0.1`, here client_ip is the IP of the ViNET client device viz. the laptop.
   
12. Place the ViNET video call from the Andoroid client side and recieve it at the peer side.
13. Now you should be able to access internet from the ViNET client device viz. the laptop.
