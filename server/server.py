import socket


TCP_IP = '127.0.0.1'
TCP_PORT = 8000
BUFFER_SIZE = 1024

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
conn, addr = s.accept
while True:
    data = conn.recv(BUFFER_SIZE)
    print('data')

conn.close()
