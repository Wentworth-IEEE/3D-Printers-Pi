import socket
import re
from Crypto.PublicKey import RSA
from Crypto import Random
from threading import Thread, Lock
import json
import base64


def generate_keys():
    """
    Returns a keypair
    """
    # Use a larger key length in practice...
    KEY_LENGTH = 2048  # Key size (in bits)
    random_gen = Random.new().read

    # Generate RSA private/public key pairs for both parties...
    keypair = RSA.generate(KEY_LENGTH, random_gen)
    return keypair


# Create keypair
keypair = generate_keys()
# Public Key as a utf-8 str
publickey = keypair.publickey().exportKey().decode('utf-8')


def decrypt_password(b64encrypted):
    """
    Decrypt the password. Sent as ascii encoded base64 data
    First encode the byte string as ascii, then decode the b64,
    then decrypt.

    Return the password as a utf-8 str
    """
    # base64ascii back to bytes
    b64bytes = b64encrypted.encode('ascii')
    encrypted_pass = base64.b64decode(b64bytes)
    return keypair.decrypt(encrypted_pass).decode('utf-8')


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


def send_message(s, message):
    """
    Send a message
    First sends the length of the message (bytes) and then sends the message.
    The sizeofmessage is always going to be 6 bytes, so the server can always
    know the size of that message.
    """
    sizeofmessage = len(message)
    sizeofmessage = '{0:06}'.format(sizeofmessage)
    sizeofmessage = sizeofmessage.encode('ascii')
    s.send(sizeofmessage)
    s.send(message)


def client_handler(conn, addr):
    """
    Handle a client message
    """
    while True:
        data = receive_json_message(conn)

        if 'request' not in data:
            # Means that this is a bad message
            return
        if data['request'] == 'PUBLICKEY':
            # Send this client the public key
            message_dict = {'publickey': publickey}
            message = json.dumps(message_dict).encode('utf-8')
            send_message(conn, message)
        elif data['request'] == 'UPDATEIP':
            # Bad message if none of these keys are in the dict
            if 'name' not in data:
                return
            if 'ip' not in data:
                return
            if 'password' not in data:
                return
            # Get the info
            name = data['name']
            ip = data['ip']
            # TODO Figure out how to check if password is valid
            password = decrypt_password(data['password'])
            print(name + ' ' + ip + ' ' + password)
            write_to_file(name, ip)
        elif data['request'] == 'DONE':
            # Close the socket
            conn.close()
            break


# Lock for the write_to_file method
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

# Set up the socket to listen
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', TCP_PORT))
s.listen()
while True:
    # Keep accepting clients and make a new thread for each
    conn, addr = s.accept()
    Thread(target=client_handler, args=(conn, addr)).start()

# Close the socket if it gets out of the while loop
conn.close()
