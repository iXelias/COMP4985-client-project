#include "../include/account.h"
#include "../include/connection.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TESTUSERNAME "Testing"
#define TESTPASSWORD "Password123"
#define LOGIN 0x0A
// #define LOGOUT 0x0C
#define CREATE_ACCOUNT 0x0D

struct networkSocket
{
    int                client_fd;
    struct sockaddr_in address;
};

int main(int argc, char *argv[])
{
    struct networkSocket data;
    char                 detected_ip[INET_ADDRSTRLEN];
    char                *manual_address;
    in_port_t            manual_port;
    data.client_fd = 0;

    manual_address = NULL;
    manual_port    = 0;

    parse_args(argc, argv, &manual_address, &manual_port);

    if(manual_address == NULL)
    {
        in_addr_t ip;
        find_address(&ip, detected_ip);
        manual_address = detected_ip;
    }

    data.client_fd = setup_client(&data.address, manual_address, manual_port);
    if(data.client_fd < 0)
    {
        exit(EXIT_FAILURE);
    }
    display_port(&data.address, manual_address);

    // Create account
    account_request(data.client_fd, TESTUSERNAME, TESTPASSWORD, CREATE_ACCOUNT);
    account_response(data.client_fd);

    // Login account
    account_request(data.client_fd, TESTUSERNAME, TESTPASSWORD, LOGIN);
    account_response(data.client_fd);

    // Logout accont
    account_logout(data.client_fd);
    account_response(data.client_fd);

    close(data.client_fd);
    return EXIT_SUCCESS;
}
