#!/usr/bin/env python3
"""Server for multithreaded (asynchronous) chat application."""
import argparse
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread

import nacl.utils
from nacl.public import PrivateKey, Box, PublicKey, EncryptedMessage


def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected." % client_address)

        public_keys[client] = PublicKey(client.recv(32))
        client.send(SERVER_PUBLIC_KEY.encode())

        box = Box(SERVER_PRIVATE_KEY, public_keys[client])
        msg = b"Greetings from the cave! Now type your name and press enter!"
        encrypted = box.encrypt(msg)
        client.send(encrypted)

        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()


def handle_client(client: socket):  # Takes client socket as argument.
    """Handles a single client connection."""
    box = Box(SERVER_PRIVATE_KEY, public_keys[client])

    try:
        name = (client.recv(BUFSIZ))
        name = box.decrypt(name)
        name = name.decode("utf8")
    except:
        print(f"{addresses[client][0]}:{addresses[client][1]} Error when decrypting username.")
        name = "error"

    welcome = 'Welcome %s! If you ever want to quit, type {quit} to exit.' % name

    client.send(encrypt_msg(welcome, client))
    msg = "%s has joined the chat!" % name
    broadcast(msg)
    clients[client] = name

    while True:
        msg = client.recv(BUFSIZ)

        if len(msg) > 0:
            decrypted_msg = box.decrypt(msg)
            decoded_msg = decrypted_msg.decode("utf8")
        else:
            decoded_msg = "quit"

        if decoded_msg != "quit":
            broadcast(decoded_msg, name + ": ")
        else:
            disconnect_msg = f"{addresses[client][0]}:{addresses[client][1]} has disconnected."
            cleanup_client(client)
            broadcast(f"{name} has left the chat.")
            print(disconnect_msg)
            break


def broadcast(msg: str, prefix=""):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""
    for sock in clients:
        res = prefix + msg
        encrypted_msg = encrypt_msg(res, sock)
        sock.send(encrypted_msg)


def cleanup_client(_client: socket):
    del public_keys[_client]
    _client.close()
    del clients[_client]


def encrypt_msg(msg: str, _client: socket) -> EncryptedMessage:
    box = Box(SERVER_PRIVATE_KEY, public_keys[_client])
    encrypted = box.encrypt(msg.encode('utf-8'))
    return encrypted


clients = {}  # socket, name
addresses = {}  # socket, client_adress
public_keys = {}  # socket, PublicKey
SERVER_PRIVATE_KEY = PrivateKey.generate()
SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.public_key


# ----Now comes the arguments part----
parser = argparse.ArgumentParser(description='This is the server for the chat.')
parser.add_argument('ip', type=str, nargs='?', default='127.0.0.1',
                    help='the ip you want to bind. (default 127.0.0.1)')

parser.add_argument('-p', '--port', type=int, nargs='?', default=33000,
                    help='the port. (default 33000)')  
parser.add_argument('-s', '--buff-size', type=int, nargs='?', default=1024,
                    help='the size of the buffer. (default 1024)')
                    
args = parser.parse_args()
HOST = args.ip
PORT = args.port
BUFSIZ = args.buff_size

ADDR = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

if __name__ == "__main__":
    SERVER.listen(5)
    print(f'[INFO] Server started on {HOST}:{PORT}, buffer size: {BUFSIZ}')
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()
