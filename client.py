import getpass
import json
import select
import socket
import string
import sys
from base64 import b64decode, b64encode

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA

# Written by Justin Sorensen and Meghan Harris with referencing
# to Rishija Mangla at the following link:
# https://github.com/Rishija/python_chatServer
#
# Program to simulate an ecrypted chat server with functions
# to hold client symmetric keys and encrypt/decrypt client
# messages.

# Function to create a symmetric key for client


def createClientSymmetricKey():
    # Generate a new symmetric key
    key = get_random_bytes(16)
    return key


# Function to encrypt symmetric key with server's
# RSA public key
#
# We referenced the following site:
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/oaep.html


def clientEncrypt(data, key):
    try:
        # Cipher used to encrypt or decrypt
        cipher = PKCS1_OAEP.new(key)

        # Build encrypted data
        ct_bytes = cipher.encrypt(data)

        return ct_bytes
    except (ValueError, KeyError):
        print("something happened")

# AES in CBC Mode encryption function for client messages
#
# We referenced the following link:
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode


def messageEncryption(message, key):
    # Generate new cipher in AES CBC mode using symmetric key
    cipher = AES.new(key, AES.MODE_CBC)

    # Encrypt message, extract iv from cipher, and put into JSON format
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv': iv, 'ciphertext': ct})
    # print(result)
    return result

# AES in CBC Mode decryption function for client messages
#
# We referenced the following link:
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode


def messageDecryption(message, key):
    try:
        # Parse JSON message for iv and cipher text
        b64 = json.loads(message)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Decrypt message with cipher
        result = unpad(cipher.decrypt(ct), AES.block_size)

        return result.decode()

    except (ValueError, KeyError):
        print("")

# Helper function (formatting)


def displayMessage():
    sys.stdout.write("me : ")
    sys.stdout.flush()

# Function to handle admin commands: admin, getusers,
# kick, and make admin


def commandTree(msg, s, isAdmin, key):
    # Client assigns themselves admin status
    result = messageEncryption(msg, key)
    if "-admin" in msg and isAdmin == False:
        password = getpass.getpass('Enter the password : ')
        if (password == 'password'):
            s.send(result.encode())
            print('You are now an admin')
            return True
        else:
            return False
    elif isAdmin and "-admin" in msg:
        print('you are already an admin')
        return True
    elif isAdmin:
        s.send(result.encode())
        return True
    elif "-getusers" in msg:
        s.send(result.encode())
        return isAdmin
    else:
        return isAdmin

# Main function to set up connection to server and
# maintain a connection while receiving and sending
# messages


def main():

    # Input to hold server address
    # serverIP = "127.0.0.1"
    serverIP = input("Enter server ip address: ")
    # Input to hold port number
    portNum = input("Enter the server's port number: ")
    # portNum = 9876
    # Boolean to hold admin status
    isAdmin = False
    # Symmetric Key
    symmetricKey = ""

    # Grab public key from file
    publicKey = RSA.importKey(open("RSApub.pem").read())

    # asks for user name
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)

    # Connect to host
    try:
        s.connect((serverIP, int(portNum)))
    except:
        print("\n Can't connect to the server \n")
        sys.exit()

    # Send server new and encrypted symmetric key
    symmetricKey = createClientSymmetricKey()
    # print(symmetricKey)
    msg = clientEncrypt(symmetricKey, publicKey)
    s.send(msg)

    # After connecting, send server encrypted name
    name = input("Enter username: ")
    name = messageEncryption(name, symmetricKey)
    s.send(name.encode())

    # Main loop to send encrypted chats
    while 1:
        socket_list = [sys.stdin, s]

        # Get the list of sockets which are readable
        rList, wList, error_list = select.select(socket_list, [], [])

        for sockfd in rList:
           # incoming message from server
            if sockfd == s:
                # Receive and decrypt message
                data = sockfd.recv(4096)
                data = data.decode()
                data = messageDecryption(data, symmetricKey)
                if not data:
                    print('\nDisconnected from server')
                    sys.exit()
                else:
                    # When client has been made an admin by another user
                    if ("-admin") in data:
                        isAdmin = True
                        print("You were made an admin.")
                        displayMessage()
                    else:
                        sys.stdout.write(data)
                        displayMessage()

            # Client sends a message
            else:
                msg = sys.stdin.readline()
                if msg.startswith('-'):
                    isAdmin = commandTree(msg, s, isAdmin, symmetricKey)
                    displayMessage()
                else:
                    msg = messageEncryption(msg, symmetricKey)
                    s.send(msg.encode())
                    displayMessage()


if __name__ == "__main__":
    main()
