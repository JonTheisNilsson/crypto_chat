# crypto_chat
Repo for the crypto course Mandatory Task2


## Introduction
This assignment is expected to be made in groups of 3-4 students.
This mandatory task will focus on using the Libsodium cryptographic library. We’ll use the Python wrapper called PyNaCl. For documentation, you’re strongly encouraged to check out  https://pynacl.readthedocs.io, where you’ll see that the examples provided are especially useful to solve this assignment. 
You need to hand in a ZIP file with the files each question is asking for.

## Tools
All the files you need for this assignment are found at https://github.com/Sebikea/crypto_chat.


## What you’re asked to do

**1. Securing a chat system**

You’ll find under the folder /chat two Python scripts:
- `server.py` implements the server of a chat system
- `client.py` implements the client of a chat system

This chat allows one or more clients to communicate with each other using TCP sockets, thanks to a server whose job is to forward each message to all clients except to the one that sent the message. You’re welcome to run the server and a few instances of the client to see how it works. It should work fine on localhost, but it also works fine if several of you are running the instances within the same network.
As it is right now, the chat is not secure. Design a simple security protocol for the chat system, incorporating encryption of the messages. Consider whether you would use either symmetric, asymmetric encryption, or both (and in which order), and describe the steps that each user would follow from the moment they join the chat until they’re able to send encrypted messages and what each user should do to decrypt and read the received messages. Try to keep it simple.

**2. Implementing a secure chat system (optional)**

Following the previous subtask, identify the parts of the code where a message is sent/received to/from the socket, and add the necessary lines of code to encrypt/decrypt the messages exchanged in the chat between every pair of users. Use the library PyNaCl to do so.
For this subtask, you need to hand in:
Python source code of both client and server programs
A screenshot showing the chat running
