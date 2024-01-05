import socket

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 8080  # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("CONNECTED")
    while True:
        for i in range(50000):
            s.send("data".encode(encoding="utf-8"))
            data = s.recv(2048)
            if data != "None".encode(encoding="utf-8"):
                print(data)
        for i in range(1):
            s.send("comms".encode(encoding="utf-8"))
            data = s.recv(2048)

print(f"Received {data!r}")