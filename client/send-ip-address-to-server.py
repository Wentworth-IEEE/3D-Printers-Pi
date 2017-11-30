import netifaces as ni
import socket
import json
from Crypto.PublicKey import RSA
from Crypto import Random
import base64


def get_ip(device):
    """
    Return the ip adress of device
    """
    return ni.ifaddresses(device)[ni.AF_INET][0]['addr']


def encode_base64_ascii(the_bytes):
    """
    Encode the byte array in base 64 and then decode into a ascii str

    Return an ascii str of the base64 encoded bytes
    """
    encoded_b64 = base64.b64encode(the_bytes)
    return encoded_b64.decode('ascii')


def encrypt_password(publickey, password):
    """
    Encrypt the password and encodes it with encode_base64_ascii

    Return the encrypted and encoded string
    """
    # Encrypt get first value of tuple because docs said second value is
    # always None for some reason
    encoded_pass = publickey.encrypt(password.encode('utf-8'), 32)[0]
    # Encode to b64 ascii
    encoded_pass_b64str = encode_base64_ascii(encoded_pass)
    return encoded_pass_b64str


def receive_json_message(conn):
    """
    Receive a json message given a connection socket

    Return the json data
    """
    # Client sends size of next message first
    message_size = int(conn.recv(6).decode('ascii'))
    # Get message given message_size
    rec_data = conn.recv(message_size)
    # Decode it as utf-8 and load as json
    data_str = rec_data.decode('utf-8')
    return json.loads(data_str)


def create_message(request, name=None, ip=None, password=None):
    """
    Creates a json message to send to the server

    requests:
    - PUBLICKEY - get the public key
    - UPDATEIP - send an update for the ip
    - DONE - close the connection
    """
    dictionary = {'request': request}
    if name is not None:
        dictionary['name'] = name
    if ip is not None:
        dictionary['ip'] = ip
    if password is not None:
        dictionary['password'] = password
    return json.dumps(dictionary).encode('utf-8')


def send_message(s, message):
    """
    Send a message
    First sends the length of the message (bytes) and then sends the message.
    The sizeofmessage is always going to be 6 bytes, so the server can always
    know the size of that message.
    """
    # send sizeofmessage message first
    sizeofmessage = len(message)
    sizeofmessage = '{0:06}'.format(sizeofmessage)
    sizeofmessage = sizeofmessage.encode('ascii')
    s.send(sizeofmessage)
    # Send actual message
    s.send(message)


# Use a larger key length in practice...
KEY_LENGTH = 2048  # Key size (in bits)
random_gen = Random.new().read

# Generate RSA private/public key pairs for both parties...
keypair = RSA.generate(KEY_LENGTH, random_gen)

# Stuff about the server
ip = get_ip('en0')
TCP_IP = 'localhost'
TCP_PORT = 8000
# TODO Temporary, not sure how I'm going to set password yet...
PASSWORD = 'stukmakenpassword'

# Create the socket, connecting to the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
# Ask for the public key
message = create_message('PUBLICKEY')
send_message(s, message)
# Get public key and make a RSA object with it
publickey_str = receive_json_message(s)['publickey']
publickey = RSA.importKey(publickey_str)
# Get the encoded password
encoded_pass_b64str = encrypt_password(publickey, PASSWORD)
# Send the update ip message
message = create_message('UPDATEIP', 'Stukmaken', ip, encoded_pass_b64str)
send_message(s, message)
# Send that it's done
message = create_message('DONE')
send_message(s, message)
# Close the connection
s.close()
