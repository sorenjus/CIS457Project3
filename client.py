import socket
import select
import string
import sys

# Helper function (formatting)

displayName = ""

def displayMessage():
    sys.stdout.write(" me : ")
    sys.stdout.flush()


def main():

    serverIP = "127.0.0.1"
    #serverIP = input("Enter server ip address: ")
    #portNum = input("Enter the server's port number: ")
    portNum = 9876

    # asks for user name
    name = input("Enter username: ")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)

    # connecting host
    try:
        s.connect((serverIP, portNum))
    except:
        print("\33[31m\33[1m Can't connect to the server \33[0m")
        sys.exit()

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
                    print('Disconnected from server')
                    sys.exit()
                else:
                    sys.stdout.write(data)
                    displayMessage()

            # user entered a message
            else:
                msg = sys.stdin.readline()
                s.send(msg.encode())
                displayMessage()


if __name__ == "__main__":
    main()
