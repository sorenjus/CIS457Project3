import getpass
import json
import select
import socket
import string
import sys
from base64 import b64decode, b64encode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import rsa


# Function to create a symmetric, private key for client


def createClientSymmetricKey():
    # Set up cipher object with cryptographic key and mode as params
    key = get_random_bytes(16)
    return key


# Function to help with encryption with AES in CBC mode


def clientEncrypt(data, key):
    # Cipher used to encrypt or decrypt
    print(key)
    try:
        cipher = AES.new(key, AES.MODE_CBC)
        print(cipher)

        # Build encrypted data
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        # print(ct_bytes)
        # print(cipher.iv)
        iv = b64encode(cipher.iv).decode('utf-8')
        print(iv)
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv': iv, 'ciphertext': ct})

        print("Result: ", result)
        return result
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
    publicKey = ""
    with open("RSApub.pem", 'rb') as public_key:
        key_data = public_key.read()
        # publicKey = rsa.PublicKey.load_pkcs1_openssl_pem(key_data)
        publicKey = key_data

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
    msg = clientEncrypt(publicKey, symmetricKey)
    print(msg.encode())
    s.send(msg.encode())
    name = input("Enter username: ")
    # After connecting, send username
    s.send(name.encode())
    # s.send(secretKey)
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
