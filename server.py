import socket
import json
import select
import signal
from base64 import b64decode, b64encode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import rsa

# Written by Justin Sorensen and Meghan Harris with referencing
# to Rishija Mangla at the following link:
# https://github.com/Rishija/python_chatServer

# Function to help with decryption with AES in CBC Mode


def serverDecrypt(data):
    # Grab public key from file
    privateKey = ""
    with open("RSApriv.pem", 'rb') as private_file:
        key_data = private_file.read()
        # privateKey = rsa.PublicKey.load_pkcs1_openssl_pem(key_data)
        privateKey = key_data

    try:

        b64 = json.loads(data)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(privateKey, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("The message was: ", pt)
        return pt

    except (ValueError, KeyError):
        print("Incorrect decryption")

# Function to handle sigkill


def sig_handler(signum, frame):
    result = input("Ctrl-c was pressed.  Exit? y or n\n")
    print(result, end="", flush=True)
    if result == 'y':
        server.close()
        exit(1)

# Function to send message to all connected clients


def send_to_all(sock, message):
    # Message not forwarded to server and sender itself
    for socket in serverList:
        if socket != server and socket != sock:
            try:
                socket.send(message)
            except:
                # if connection not available
                socket.close()
                serverList.remove(socket)

# Function to send messages to selected client


def send_to_individual(message, username, userSocket):
    userExists = False
    for item in userArr:
        if item == username:
            userExists = True
    if userExists:
        if userSocket[username] is not None:
            try:
                userSocket[username].send(message.encode())
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
        send_to_all(removed.encode())
    except:
        offline = "\n" + username + " is offline\n"
        sock.send(offline.encode())

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
                temp = sockfd.recv(buffer)
                symmetricKey = serverDecrypt(temp.decode())
                user = sockfd.recv(buffer)
                user = user.decode()
                serverList.append(sockfd)
                currentUsers[clientAddr] = ""
                print(currentUsers)

                # Check for duplicate usernames
                if user in userArr:
                    duplicateUsername = "Username already taken!\n"
                    sockfd.send(duplicateUsername.encode())
                    del currentUsers[clientAddr]
                    serverList.remove(sockfd)
                    sockfd.close()
                    continue
                else:
                    # add name and address
                    currentUsers[clientAddr] = user
                    print("Client (%s, %s) connected" %
                          clientAddr, " [", currentUsers[clientAddr], "]")
                    welcome = "\nWelcome\n"
                    sockfd.send(welcome.encode())
                    userSockets[user] = sockfd
                    userArr.append(user)
                    newUserMsg = "\n" + user + \
                        " is online\n"
                    send_to_all(
                        sockfd, newUserMsg.encode())

            # Incoming message from a client
            else:
                try:
                    data1 = sock.recv(buffer)
                    data1 = data1.decode()
                    receivedMesssage = data1[:data1.index("\n")]
                    print("\ndata received: ", receivedMesssage)
                    # Retrieve socket address from client
                    i, p = sock.getpeername()
                    if receivedMesssage == "quit":
                        msg = "\n" + \
                            currentUsers[(i, p)]+" left the conversation\n"
                        userArr.remove(currentUsers[(i, p)])
                        send_to_all(sock, msg.encode())
                        print("\nClient (%s, %s) is offline" %
                              (i, p), " [", currentUsers[(i, p)], "]\n")
                        del currentUsers[(i, p)]
                        serverList.remove(sock)
                        sock.close()
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
                                    str1 += element + ", "
                                else:
                                    str1 += element
                                counter += 1
                            str1 += "\n"
                            sock.send(str1.encode())
                        # Client admin removes another client from the server
                        elif ('-kick') in receivedMesssage:
                            for admin in admins:
                                if currentUsers[(i, p)] == admin:
                                    isAdmin = True
                            if isAdmin:
                                arr = receivedMesssage.split(" ")
                                username = arr[1]
                                for user in userArr:
                                    if user == username:
                                        kick_user(username, userSockets, sock)
                                        userArr.remove(user)
                                        continue
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
                                    if item == username:
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
                        send_to_all(sock, msg.encode())

                # User exits without quit command
                except:
                    (i, p) = sock.getpeername()
                    msg = "\n"+currentUsers[(i, p)
                                            ]+" left the conversation unexpectedly\n"
                    send_to_all(sock, msg.encode())
                    print("Client (%s, %s) is offline" %
                          (i, p), " [", currentUsers[(i, p)], "]\n")
                    userArr.remove(currentUsers[(i, p)])
                    del currentUsers[(i, p)]
                    serverList.remove(sock)
                    sock.close()
                    continue

    server.close()
