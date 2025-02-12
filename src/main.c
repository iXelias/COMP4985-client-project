#include <../include/account.h>
#include <../include/connection.h>
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

int main(void)
{
    int server_sock_fd;
    server_sock_fd = connect_to_server();

    // Create account
    account_request(server_sock_fd, TESTUSERNAME, TESTPASSWORD, CREATE_ACCOUNT);
    account_response(server_sock_fd);

    // Login account
    account_request(server_sock_fd, TESTUSERNAME, TESTPASSWORD, LOGIN);
    account_response(server_sock_fd);

    // Logout accont
    account_logout(server_sock_fd);
    account_response(server_sock_fd);

    close(server_sock_fd);
    return EXIT_SUCCESS;
}
