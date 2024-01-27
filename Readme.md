TO-DO
  1. Use case
    1. Peer to peer setup using only phone.
    2. Server installed at linux routers.
  2. Security Analysis
    1. Use stenography
    2. Identify various algorithms used for detection and show effectiveness against them.


ip6tables -t mangle -A INPUT -i rmnet_data1 -p UDP -j NFQUEUE --queue-num 5
ip6tables -t mangle -A OUTPUT -o rmnet_data1 -p UDP -j NFQUEUE --queue-num 5


CLIENT
<!-- iptables -t nat -A PREROUTING -i wlan0 -j NFQUEUE --queue-num 10 -->
iptables -A OUTPUT -p icmp -s self_ip -j DROP

SERVER
<!-- iptables -t mangle -A INPUT -i rmnet_data2 -j NFQUEUE --queue-num 10
iptables -t mangle -A INPUT -i wlan0 -j NFQUEUE --queue-num 10 -->
iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE