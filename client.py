import socket
import select
import string
import sys
import getpass

# Helper function (formatting)

displayName = ""


def displayMessage():
    sys.stdout.write(" me : ")
    sys.stdout.flush()


def commandTree(msg, s, isAdmin):
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
        print('other command stuff')
        return True
    elif "-getusers" in msg:
        s.send(msg.encode())
        return isAdmin
    else:
        return isAdmin


def main():

    serverIP = "127.0.0.1"
    #serverIP = input("Enter server ip address: ")
    #portNum = input("Enter the server's port number: ")
    portNum = 9876
    isAdmin = False

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
                    print('\nDisconnected from server')
                    sys.exit()
                else:
                    if ("-admin") in data:
                        isAdmin = True
                        print("You were made an admin.")
                        displayMessage()
                    else:
                        sys.stdout.write(data)
                        displayMessage()

            # user entered a message
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
