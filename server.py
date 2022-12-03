import socket
import json
import select
import signal
from base64 import b64decode, b64encode

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA

# Written by Justin Sorensen and Meghan Harris with referencing
# to Rishija Mangla at the following link:
# https://github.com/Rishija/python_chatServer

# Function to help with decryption with AES in CBC Mode


def serverDecrypt(data):
    # Grab public key from file
    privateKey = RSA.importKey(open("RSApriv.pem").read())

    try:
        cipher = PKCS1_OAEP.new(privateKey)
        message = cipher.decrypt(data)
        # print("The message was: ", message)
        return message

    except (ValueError, KeyError):
        print("")

# AES in CBC Mode encryption function


def messageEncryption(message, key):
    cipher = AES.new(key, AES.MODE_CBC)

    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv': iv, 'ciphertext': ct})
    # print(result)
    return result

# AES in CBC Mode decryption function


def messageDecryption(message, key):
    try:
        b64 = json.loads(message)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        result = unpad(cipher.decrypt(ct), AES.block_size)
        # print("The message was: ", result)
        return result.decode()

    except (ValueError, KeyError):
        print("")

# Function to handle sigkill


def sig_handler(signum, frame):
    result = input("Ctrl-c was pressed.  Exit? y or n\n")
    print(result, end="\n", flush=True)
    if result == 'y':
        server.close()
        exit(1)

# Function to send message to all connected clients


def send_to_all(sock, message):
    # Message not forwarded to server and sender itself
    counter = -1
    for socket in serverList:
        # print(userArr[counter].name)
        if socket != server and socket != sock:
            try:
                result = messageEncryption(message, userArr[counter].key)
                socket.send(result.encode())
            except:
                # if connection not available
                socket.close()
                serverList.remove(socket)
        counter += 1

# Function to send messages to selected client


def send_to_individual(message, username, userSocket):
    userExists = False
    userKey = ""
    for item in userArr:
        if item.name == username:
            userExists = True
            userKey = item.key
    if userExists:
        if userSocket[username] is not None:
            try:
                result = messageEncryption(message, userKey)
                userSocket[username].send(result.encode())
            except:
                # if connection not available
                userSocket[username].close()
                serverList.remove(userSocket[username])

# Function to kick a particular user offline


def kick_user(username, userSockets, sock):

    try:
        userSockets[username].close()
        serverList.remove(userSockets[username])
        del userSockets[username]
        removed = "\n" + username + " has been kicked from the conversation\n"
        send_to_all(sock, removed)
    except:
        offline = "\n" + username + " is offline\n"
        send_to_all(sock, offline)
        # sock.send(offline.encode())


class users:
    def __init__(self, name, key):
        self.name = name
        self.key = key

# Main driver function to set up connections and handle
# client communications


if __name__ == "__main__":
    user = ""
    # dictionary to store address corresponding to username
    currentUsers = {}
    # List of approved admins
    admins = []
    # List of current users
    userArr = []
    # List to keep track of socket descriptors
    serverList = []
    # Dictionary of user sockets
    userSockets = {}
    # Variable to hold incoming data
    buffer = 4096
    keyBuffer = 4096
    nameBuffer = 4096
    # Variable to hold port number input
    # portNum = input("Enter the server's port number: ")
    portNum = 9876
    # Server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Handle ctrl-c from user
    signal.signal(signal.SIGINT, sig_handler)

    server.bind(("", int(portNum)))
    server.listen(10)  # listen atmost 10 connection at one time

    # Add server socket to the list of readable connections
    serverList.append(server)

    print("Server started")

    while 1:
        # Get the list sockets which are ready to be read through select
        rList, wList, error_sockets = select.select(serverList, [], [])
        isAdmin = False

        for sock in rList:
            # New connection
            if sock == server:
                # Accept new connections through server socket
                sockfd, clientAddr = server.accept()
                temp = sockfd.recv(keyBuffer)
                symmetricKey = serverDecrypt(temp)
                user = sockfd.recv(nameBuffer)
                user = user.decode()
                user = messageDecryption(user, symmetricKey)
                serverList.append(sockfd)
                currentUsers[clientAddr] = ""

                # Check for duplicate usernames
                duplicate = False
                for element in userArr:
                    if element.name == user:
                        duplicateUsername = "Username already taken!\n"
                        duplicateUsername = messageEncryption(
                            duplicateUsername, symmetricKey)
                        sockfd.send(duplicateUsername.encode())
                        del currentUsers[clientAddr]
                        serverList.remove(sockfd)
                        sockfd.close()
                        duplicate = True
                        continue
                if duplicate:
                    continue
                # add name and address
                currentUsers[clientAddr] = user
                print("Client (%s, %s) connected" %
                      clientAddr, " [", currentUsers[clientAddr], "]")
                welcome = "\nWelcome\n"
                welcome = messageEncryption(welcome, symmetricKey)
                sockfd.send(welcome.encode())
                userSockets[user] = sockfd
                userArr.append(users(user, symmetricKey))
                for obj in userArr:
                    print(obj.name, obj.key, sep=", ")
                newUserMsg = "\n" + user + \
                    " is online\n"
                send_to_all(
                    sockfd, newUserMsg)
                print(currentUsers)
            # Incoming message from a client
            else:
                try:
                    data1 = sock.recv(buffer)
                    data1 = data1.decode()
                    i, p = sock.getpeername()
                    for user in userArr:
                        if user.name == currentUsers[(i, p)]:
                            print(user.name)
                            data1 = messageDecryption(data1, user.key)
                    receivedMesssage = data1[:data1.index("\n")]
                    print("\ndata received: ", receivedMesssage)
                    # Retrieve socket address from client
                    if receivedMesssage == "quit":
                        msg = "\n" + \
                            currentUsers[(i, p)]+" left the conversation\n"
                        for user in userArr:
                            if user.name == currentUsers[(i, p)]:
                                print("Username: ", user.name)
                                userArr.remove(user)
                        for obj in userArr:
                            print(obj.name, obj.key, sep=", ")
                        print("\nClient (%s, %s) is offline" %
                              (i, p), " [", currentUsers[(i, p)], "]\n")
                        del currentUsers[(i, p)]
                        serverList.remove(sock)
                        sock.close()
                        send_to_all(sock, msg)
                    # Handle client admin commands
                    elif receivedMesssage.startswith('-'):
                        # Client assigned admin status
                        if ('-admin') in receivedMesssage:
                            admins.append(currentUsers[(i, p)])
                            print(list(admins))
                        # Client requests all usernames
                        elif ('-getusers') in receivedMesssage:
                            str1 = "\n"
                            counter = 0
                            for element in userArr:
                                if counter < len(userArr) - 1:
                                    str1 += element.name + ", "
                                else:
                                    str1 += element.name
                                counter += 1
                            str1 += "\n"
                            for user in userArr:
                                if user.name == currentUsers[(i, p)]:
                                    str1 = messageEncryption(str1, user.key)
                            sock.send(str1.encode())
                        # Client admin removes another client from the server
                        elif ('-kick') in receivedMesssage:
                            for admin in admins:
                                if currentUsers[(i, p)] == admin:
                                    isAdmin = True
                            if isAdmin:
                                arr = receivedMesssage.split(" ")
                                if len(arr) > 1:
                                    username = arr[1]
                                    for user in userArr:
                                        if user.name == username:
                                            userArr.remove(user)
                                            kick_user(
                                                username, userSockets, sock)
                                            continue
                                else:
                                    for user in userArr:
                                        if user.name == currentUsers[(i, p)]:
                                            msg = "Error: no username provided.\n"
                                            msg = messageEncryption(
                                                msg, user.key)
                                            sock.send(msg.encode())

                        # Client admin makes another client an admin
                        elif ('-makeadmin') in receivedMesssage:
                            for admin in admins:
                                if currentUsers[(i, p)] == admin:
                                    isAdmin = True

                            arr = receivedMesssage.split(" ")
                            if len(arr) > 1:
                                notAdmin = True
                                username = arr[1]
                                userExists = False
                                for item in userArr:
                                    if item.name == username:
                                        userExists = True
                                for admin in admins:
                                    if username == admin:
                                        notAdmin = False
                                if isAdmin and userExists and notAdmin:
                                    admins.append(username)
                                    msg = '\n-admin\n'
                                    print("Admins: ", list(admins))
                                    send_to_individual(
                                        msg, username, userSockets)
                    # Client sending another client a private message
                    elif receivedMesssage.startswith('.private'):
                        arr = receivedMesssage.split(" ")
                        username = arr[1]
                        arr.pop(1)
                        str1 = "\n" + currentUsers[(i, p)]+": "
                        for item in arr:
                            str1 += item + " "
                        str1 += "\n"
                        send_to_individual(str1, username, userSockets)
                    # Client broadcasts message to all clients
                    else:
                        msg = "\n" + \
                            currentUsers[(i, p)]+": " + \
                            receivedMesssage+"\n"
                        send_to_all(sock, msg)

                # User exits without quit command
                except:
                    (i, p) = sock.getpeername()
                    msg = "\n"+currentUsers[(i, p)
                                            ]+" left the conversation unexpectedly\n"
                    print("Client (%s, %s) is offline" %
                          (i, p), " [", currentUsers[(i, p)], "]\n")
                    for user in userArr:
                        if user.name == currentUsers[(i, p)]:
                            userArr.remove(user)
                    del currentUsers[(i, p)]
                    serverList.remove(sock)
                    sock.close()
                    send_to_all(sock, msg)
                    continue

    server.close()
