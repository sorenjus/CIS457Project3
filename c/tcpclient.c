#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

bool running = true;

int main(int argc, char **argv)
{
    // TCP instead of UDP for data sent through socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    int port;
    char ip[20] = "";
    char *userName;

    printf("Enter an IP address: \n");
    fgets(ip, 5000, stdin);
    printf("Enter a port number: \n");
    scanf("%d%*c", &port);
    struct sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(port);
    serveraddr.sin_addr.s_addr = inet_addr(ip);

    int n = connect(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    if (n < 0)
    {
        printf("There was a problem connecting\n");
        close(sockfd);
        return 1;
    }

    printf("Enter your username : \n");
    char userInput[5000];
    scanf("%s", userInput);
    userName = userInput;
    char createUser[30] = "-create username ";
    
    memcpy(&createUser[17], userInput, sizeof(userInput));

    send(sockfd, createUser, strlen(createUser) + 1, 0);
    do
    {
        /*char line_segment[255] = "";
        int f = recv(sockfd, line_segment, 256, 0);
        if (f == -1)
        {
            remove(filename);
            fclose(file);
            running = false;
            perror("Error receiving: \n");
        }
        char to_file[255] = "";
        memcpy(to_file, line_segment, sizeof(line_segment));
        if (strstr(to_file, "-1") != NULL)
        {
            running = false;
            fclose(file);
        }
        else{
            fputs(to_file, file);
            printf("Printed line to file: %s\n", to_file);
            }*/
    } while (running);

    close(sockfd);
    return 0;
}
