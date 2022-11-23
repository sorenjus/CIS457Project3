import socket
import select

# Function to send message to all connected clients
# TODO: Send to individuals and all online users -- be able to
# get a list of all users.

# TODO: Admin commands


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


def send_to_individual(message, username, userSocket):
    if userSocket[username] is not None:
        try:
            userSocket[username].send(message.encode())
        except:
            # if connection not available
            userSocket[username].close()
            serverList.remove(userSocket[username])

def kick_user(username, userSockets, sock):
    
        try:
            print('search for user')
            # for user in currentUsers.values:
            #     if user in username:
            #         del user
            print('close socket')
            userSockets[username].close()
            serverList.remove(userSockets[username])
            del userSockets[username]
            removed = "\n" + username + "has been kicked from the conversation\n"
            send_to_all(removed.encode())
        except:
            offline = "\n" + username + "is offline"
            sock.send(offline.encode())
    
        

if __name__ == "__main__":
    user = ""
    # dictionary to store address corresponding to username
    currentUsers = {}
    admins = []
    # List to keep track of socket descriptors
    serverList = []
    userSockets = {}
    admin = []
    buffer = 4096
    #portNum = input("Enter the server's port number: ")
    portNum = 9876

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.bind(("localhost", portNum))
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
                # Handle the case in which there is a new connection recieved through server_socket
                sockfd, clientAddr = server.accept()
                user = sockfd.recv(buffer)
                user = user.decode()
                serverList.append(sockfd)
                currentUsers[clientAddr] = ""
                # print "record and conn list ",record,connected_list
                print(currentUsers)

        # if repeated username
                if user in currentUsers.values():
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
                    welcome = "Welcome\n"
                    sockfd.send(welcome.encode())
                    userSockets[user] = sockfd
                    newUserMsg = "" + user + \
                        " is online\n"
                    send_to_all(
                        sockfd, newUserMsg.encode())

            # Some incoming message from a client
            else:
                # Data from client
                try:
                    data1 = sock.recv(buffer)
                    data1 = data1.decode()
                    # print "sock is: ",sock
                    receivedMesssage = data1[:data1.index("\n")]
                    # data = data1
                    print("\ndata received: ", receivedMesssage)

    # get addr of client sending the message
                    i, p = sock.getpeername()
                    if receivedMesssage == "quit":
                        msg = "\r\33[1m"+"\33[31m " + \
                            currentUsers[(i, p)]+" left the conversation\n"

                        send_to_all(sock, msg.encode())
                        print("Client (%s, %s) is offline" %
                              (i, p), " [", currentUsers[(i, p)], "]")
                        del currentUsers[(i, p)]
                        serverList.remove(sock)
                        sock.close()
                    elif receivedMesssage.startswith('-'):
                        if ('-admin') in receivedMesssage:
                            admins.append(currentUsers[(i, p)])
                            print(admins[0])
                        elif ('-getusers') in receivedMesssage:
                            str1 = "\n"
                            counter = 0
                            for element in currentUsers.values():
                                if counter < len(currentUsers) - 1:
                                    str1 += element + ", "
                                else:
                                    str1 += element
                                counter += 1
                            str1 += "\n"
                            sock.send(str1.encode())
                        elif ('-kick') in receivedMesssage:
                            for admin in admins:
                                if currentUsers[(i, p)] == admin:
                                    isAdmin = True
                                    print(isAdmin)
                            if isAdmin:
                                print('split string')
                                arr = receivedMesssage.split(" ")
                                username = arr[1]
                                print('send to kick ' + username)
                                if userSockets[username] is not None:
                                    print('kickable')
                                    kick_user(username, userSockets, sock)
                                else:
                                    print('offline')
                                    offline = "\n" + username + "is offline"
                                    sock.send(offline.encode())

                    elif receivedMesssage.startswith('.private'):
                        arr = receivedMesssage.split(" ")
                        username = arr[1]
                        arr.pop(1)
                        str1 = "\n" + currentUsers[(i, p)]+": "
                        for item in arr:
                            str1 += item + " "
                        str1 += "\n"
                        print(str1)
                        send_to_individual(str1, username, userSockets)
                    else:
                        msg = "\r\33[1m"+"\33[35m " + \
                            currentUsers[(i, p)]+": "+"\33[0m" + \
                            receivedMesssage+"\n"
                        send_to_all(sock, msg.encode())

        # abrupt user exit
                except:
                    (i, p) = sock.getpeername()
                    msg = "\r\33[31m \33[1m"+currentUsers[(i, p)
                                                          ]+" left the conversation unexpectedly\33[0m\n"
                    send_to_all(sock, msg.encode())
                    print("Client (%s, %s) is offline" %
                          (i, p), " [", currentUsers[(i, p)], "]\n")
                    del currentUsers[(i, p)]
                    serverList.remove(sock)
                    sock.close()
                    continue

    server.close()
