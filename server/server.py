import socket
import re


TCP_PORT = 8000
BUFFER_SIZE = 1024

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', TCP_PORT))
s.listen(1)
conn, addr = s.accept()

data = conn.recv(BUFFER_SIZE)

data = data.decode('utf-8')
data = data.split()

name = data[0]
ip = data[1]


final_file = ''
with open('index.html', 'r') as f:
    for line in f:
        if name in line:
            regex = r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]'
            line_ip = re.findall(regex, line)[0]
            final_file += line.replace(line_ip, ip)
        else:
            final_file += line

with open('index.html', 'w') as f:
    for line in final_file:
        f.write(line)

conn.close()
