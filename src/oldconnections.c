#include <../include/connection.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SERVER_PORT 39289
#define TEMP_IP "192.168.0.119"

int connect_to_server(void)
{
    struct sockaddr_in server_addr;
    int                sockfd;
    socklen_t          server_addr_len = sizeof(server_addr);
    server_addr.sin_family             = AF_INET;
    server_addr.sin_port               = htons(SERVER_PORT);
    inet_pton(AF_INET, TEMP_IP, &server_addr.sin_addr);

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1)
    {
        perror("socket creation failed...\n");
        exit(EXIT_FAILURE);
    }
    printf("Socket created\n");

    // Connect to server
    if(connect(sockfd, (struct sockaddr *)&server_addr, server_addr_len) != 0)
    {
        perror("connecting to server failed...\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("Connection to server established...\n");

    return sockfd;
}
