import socket
import re
from Crypto.Cipher import AES
from threading import Thread, Lock


def client_handler(conn, addr):
    """
    Handle a client message
    """
    data = conn.recv(BUFFER_SIZE)
    data = data.decode('utf-8')
    data = data.split()

    name = data[0]
    ip = data[1]
    print(name + ' ' + ip)
    write_to_file(name, ip)


file_lock = Lock()


def write_to_file(name, ip):
    """
    Change a printers ip if it gets a connection

    (Synchronized)
    """
    file_lock.acquire()
    # Read in file and replace the ip
    final_file = ''
    with open('index.html', 'r') as f:
        for line in f:
            if name in line:
                regex = r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
                regex_find = re.findall(regex, line)
                if len(regex_find) != 1:
                    continue
                line_ip = regex_find[0]
                final_file += line.replace(line_ip, ip)
            else:
                final_file += line

    # Write to the file
    with open('index.html', 'w') as f:
        for line in final_file:
            f.write(line)
    file_lock.release()


"""
Start the server
"""

TCP_PORT = 8000
BUFFER_SIZE = 1024

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', TCP_PORT))
s.listen()
while True:
    conn, addr = s.accept()
    Thread(target=client_handler, args=(conn, addr)).start()


conn.close()
