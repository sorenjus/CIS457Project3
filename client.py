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


# Function to create a symmetric, private key for client


def createClientSymmetricKey():
    # Generate a new symmetric key
    key = get_random_bytes(16)
    return key


# Function to help with encryption with AES in CBC mode


def clientEncrypt(data, key):
    try:
        # Cipher used to encrypt or decrypt
        cipher = PKCS1_OAEP.new(key)

        # Build encrypted data
        ct_bytes = cipher.encrypt(data)

        return ct_bytes
    except (ValueError, KeyError):
        print("something happened")

# Helper function (formatting)


def displayMessage():
    sys.stdout.write("me : ")
    sys.stdout.flush()

# Function to handle admin commands


def commandTree(msg, s, isAdmin):
    # Client assigns themselves admin status
    if "-admin" in msg and isAdmin == False:
        password = getpass.getpass('Enter the password : ')
        if (password == 'password'):
            s.send(msg.encode())
            print('You are now an admin')
            return True
        else:
            return False
    elif isAdmin and "-admin" in msg:
        print('you are already an admin')
        return True
    elif isAdmin:
        s.send(msg.encode())
        return True
    elif "-getusers" in msg:
        s.send(msg.encode())
        return isAdmin
    else:
        return isAdmin

# Main function to set up connection to server and
# maintain a connection while receiving and sending
# messages


def main():

    serverIP = "127.0.0.1"
    # Input to hold server address
    # serverIP = input("Enter server ip address: ")
    # Input to hold port number
    # portNum = input("Enter the server's port number: ")
    portNum = 9876
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

    symmetricKey = createClientSymmetricKey()
    print(symmetricKey)
    msg = clientEncrypt(symmetricKey, publicKey)
    print(msg)
    s.send(msg)
    name = input("Enter username: ")
    # After connecting, send username
    s.send(name.encode())
    while 1:
        socket_list = [sys.stdin, s]

        # Get the list of sockets which are readable
        rList, wList, error_list = select.select(socket_list, [], [])

        for sockfd in rList:
           # incoming message from server
            if sockfd == s:
                data = sockfd.recv(4096)
                data = data.decode()
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
                    isAdmin = commandTree(msg, s, isAdmin)
                    displayMessage()
                else:
                    s.send(msg.encode())
                    displayMessage()


if __name__ == "__main__":
    main()
