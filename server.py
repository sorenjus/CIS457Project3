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


if __name__ == "__main__":
    user = ""
    # dictionary to store address corresponding to username
    currentUsers = {}
    # List to keep track of socket descriptors
    serverList = []
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

        # if repeated username
                if user in currentUsers.values():
                    duplicateUsername = "\r\33[31m\33[1m Username already taken!\n\33[0m"
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
                    newUserMsg = "" + user + \
                        " joined"
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
                            currentUsers[(i, p)]+" left the conversation \33[0m\n"

                        send_to_all(sock, msg.encode())
                        print("Client (%s, %s) is offline" %
                              (i, p), " [", currentUsers[(i, p)], "]")
                        del currentUsers[(i, p)]
                        serverList.remove(sock)
                        sock.close()
                        continue

                    else:
                        msg = "\r\33[1m"+"\33[35m " + \
                            currentUsers[(i, p)]+": "+"\33[0m"+receivedMesssage+"\n"
                        send_to_all(sock, msg.encode())

        # abrupt user exit
                except:
                    (i, p) = sock.getpeername()
                    msg = "\r\33[31m \33[1m"+currentUsers[(i, p)
                                                    ]+" left the conversation unexpectedly\33[0m\n"
                    send_to_all(sock, msg.encode())
                    print("Client (%s, %s) is offline (error)" %
                          (i, p), " [", currentUsers[(i, p)], "]\n")
                    del currentUsers[(i, p)]
                    serverList.remove(sock)
                    sock.close()
                    continue

    server.close()
