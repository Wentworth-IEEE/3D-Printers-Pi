import socket


TCP_PORT = 8000
BUFFER_SIZE = 1024

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', TCP_PORT))
s.listen(1)
conn, addr = s.accept()

data = conn.recv(BUFFER_SIZE)
print(data.decode('utf-8'))

conn.close()
