import netifaces as ni
import socket


def get_ip():
    return ni.ifaddresses('en0')[ni.AF_INET][0]['addr']


ip = get_ip()
TCP_IP = 'localhost'
TCP_PORT = 8000
BUFFER_SIZE = 1024

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
message = b'Stukmaken ' + ip.encode('utf-8')
s.send(message)
s.close()
