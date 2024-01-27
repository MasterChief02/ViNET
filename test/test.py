# write a python program to open a socket and send data into it in interval of 5 secs

import socket
import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# socket will listen on port 8080
s.bind(('127.0.0.1', 8080))
s.listen(5)
(clientsocket, address) = s.accept()

while True:
    # send data to socket
    clientsocket.send(b'Hello')
    # sleep of 1 sec
    time.sleep(2)

# close socket
s.close()


