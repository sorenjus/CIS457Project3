#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/select.h>
#include <stdlib.h>

/* Program by Meghan Harris and Profesor Kalafut */

int main(int argc, char **argv)
{
    // TCP instead of UDP for data sent through socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    fd_set sockets;
    FD_ZERO(&sockets);
    FD_SET(sockfd, &sockets);

    int port;

    printf("Enter a port number: \n");
    scanf("%d%*c", &port);

    struct sockaddr_in serveraddr, clientaddr;
    serveraddr.sin_family = AF_INET;
    // Port for TCP different than port for UDP
    // Because interpreted relative to the protocol
    // Differentiated at the Transport layer
    serveraddr.sin_port = htons(port);
    serveraddr.sin_addr.s_addr = INADDR_ANY;

    bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    // Says to listen for connections - other side of the "connect" statement
    // 10 is the backlog - how many connections willing to make that we haven't
    // accepted
    listen(sockfd, 10);
    while (1)
    {
        fd_set tmpset = sockets;
        int r = select(FD_SETSIZE, &tmpset, NULL, NULL, NULL);
        if (r < 0)
        {
            perror("Error\n");
        }
        // int clientsocket;
        // Does the socket have data to read?
        if (FD_ISSET(sockfd, &tmpset))
        {
            socklen_t len = sizeof(struct sockaddr_in);
            // clientaddr filled in with the info and clientsocket is what socket
            // we need to communicate on
            int clientsocket = accept(sockfd, (struct sockaddr *)&clientaddr, &len);
            FD_SET(clientsocket, &sockets);
        }

        for (int i = 0; i < FD_SETSIZE; ++i)
        {
            if (FD_ISSET(i, &tmpset) && i != sockfd)
            {
                char line[5000];
                int n = recv(i, line, 5000, 0);
                if (n < 0)
                {
                    perror("There was a problem: \n");
                }
                printf("Got from client: %s\n", line);
                FILE *file;
                file = fopen(line, "r+");
                if (file == NULL)
                {
                    printf("Error! Could not open file\n");
                    char errorLine[263] = "Error! Could not open file.";
                    send(i, errorLine, sizeof(errorLine) + 1, 0);
                    exit(-1);
                }
                do
                {
                    char reply[255] = "";

                    fgets(reply, 255, file);
                    send(i, reply, 256, 0);
                    printf("Sent : %s\n", reply);
                } while (!feof(file));
                printf("\nDone\n\n");
                char *done = "-1";
                send(i, done, strlen(done) + 1, 0);
                FD_CLR(i, &sockets);
                close(i);
            }
        }
    }

    close(sockfd);
    return 0;
}
