import netifaces as ni
import socket


def get_ip():
    return ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']


ip = get_ip()
TCP_IP = '10.200.139.185'
TCP_PORT = 8000
BUFFER_SIZE = 1024

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
s.send(ip)
s.close()
