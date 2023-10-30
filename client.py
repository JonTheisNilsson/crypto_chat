#!/usr/bin/env python3
"""Script for Tkinter GUI chat client."""
import argparse
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter

from nacl.public import PrivateKey, Box, PublicKey
from nacl.utils import EncryptedMessage

title_chat = 'Chatter'


def receive():
    """Handles receiving of messages."""
    global title_chat, SERVER_PUBLIC_KEY, BOX

    # exchange keys
    client_socket.send(CLIENT_PUBLIC_KEY.encode())
    SERVER_PUBLIC_KEY = PublicKey(client_socket.recv(32))
    BOX = Box(CLIENT_PRIVATE_KEY, SERVER_PUBLIC_KEY)
    print(SERVER_PUBLIC_KEY)


    while True:
        try:
            msg = client_socket.recv(BUFSIZ)
            # print(f"msg received: {msg}")

            #decrypted_msg = decrypt_msg(msg)
            decrypted_msg = BOX.decrypt(msg).decode()
            #return decrypted.decode('utf-8')

            # remove name and :
            # try:
            #     index = decrypted_msg.index(":")
            #     decrypted_msg = decrypted_msg[index+1:]
            # except:
            #     pass

            msg_list.insert(tkinter.END, decrypted_msg)
            if decrypted_msg.startswith('Welcome') and title_chat == 'Chatter':
                title_chat += ' ' + decrypted_msg.split()[1]
                top.title(title_chat)
        except OSError:  # Possibly client has left the chat.
            break


def send(event=None):  # event is passed by binders.
    """Handles sending of messages."""
    msg = my_msg.get()

    encrypted_msg = encrypt_msg(msg)
    print(encrypted_msg)
    my_msg.set("")  # Clears input field.
    client_socket.send(encrypted_msg)
    if msg == "{quit}":
        client_socket.close()
        top.quit()


def on_closing(event=None):
    """This function is to be called when the window is closed."""
    my_msg.set("{quit}")
    send()


def encrypt_msg(msg: str) -> EncryptedMessage:
    encrypted = BOX.encrypt(bytes(msg.encode()))
    return encrypted


def decrypt_msg(msg: EncryptedMessage) -> str:
    decrypted = BOX.decrypt(msg.decode())
    return decrypted.decode('utf-8')


top = tkinter.Tk()
top.title(title_chat)

messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()  # For the messages to be sent.
my_msg.set("Username?")
scrollbar = tkinter.Scrollbar(messages_frame)  # To navigate through past messages.
# Following will contain the messages.
msg_list = tkinter.Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
messages_frame.pack()


entry_field = tkinter.Entry(top, textvariable=my_msg)
entry_field.bind("<Return>", send)
entry_field.pack()
send_button = tkinter.Button(top, text="Send", command=send)
send_button.pack()

top.protocol("WM_DELETE_WINDOW", on_closing)

# ----Now comes the arguments part----
parser = argparse.ArgumentParser(description='This is the client for the chat.')
parser.add_argument('ip', type=str, nargs='?', default='127.0.0.1',
                    help='the ip you want to connect to. (default 127.0.0.1)')

parser.add_argument('-p', '--port', type=int, nargs='?', default=33000,
                    help='the port. (default 33000)')  
parser.add_argument('-s', '--buff-size', type=int, nargs='?', default=1024,
                    help='the size of the buffer. (default 1024)')
                    
args = parser.parse_args()
HOST = args.ip
PORT = args.port
BUFSIZ = args.buff_size
ADDR = (HOST, PORT)
CLIENT_PRIVATE_KEY = PrivateKey.generate()
CLIENT_PUBLIC_KEY = CLIENT_PRIVATE_KEY.public_key
SERVER_PUBLIC_KEY = None
BOX: Box = None

# ----Now comes the sockets part----
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)
print(f'[INFO] Connected to {HOST}:{PORT}, buffer size: {BUFSIZ}')
receive_thread = Thread(target=receive)
receive_thread.start()
tkinter.mainloop()  # Starts GUI execution.
