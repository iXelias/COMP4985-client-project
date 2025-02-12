#include <../include/account.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PACKET_BUFFER_SIZE 64
#define LOGOUT_BUFFER_SIZE 6
#define PLACEHOLDER 0x00
#define ACCOUNT_CREATE_SUCCESS 0x00
#define ACC_LOGIN 0x0A
#define ACC_LOGOUT 0x0C
#define ACC_CREATE 0x0D
// #define SEQUENCE_TAG 0x30
#define UTF8STRING_TAG 0x0C
#define ACC_LOGIN_SUCCESS_TAG 0x0B
#define SYS_ERROR_TAG 0x01
#define BIT_MASK 0xFF
#define HIGH_BYTE_SHIFT 8
#define LOGIN_RESPONSE_PACKET 6
#define ERROR_RESPONSE_PACKET 6

void account_request(int sock, const char *username, const char *password, int request_type)
{
    // Header Structure for account request
    unsigned char header_packet[PACKET_BUFFER_SIZE];
    unsigned long payload_start;
    // unsigned long sequence_start;
    unsigned long username_length;
    unsigned long password_length;
    unsigned long payload_length;
    unsigned long position = 0;

    // Packet Type (Example: ACC_Login = 0x0A)
    if(request_type == ACC_LOGIN)
    {
        header_packet[position++] = ACC_LOGIN;
    }
    else if(request_type == ACC_CREATE)
    {
        header_packet[position++] = ACC_CREATE;
    }

    // Version
    header_packet[position++] = 0x01;

    // Sender ID
    header_packet[position++] = PLACEHOLDER;
    header_packet[position++] = PLACEHOLDER;

    // Payload Length
    payload_start             = position;
    header_packet[position++] = PLACEHOLDER;    // Placeholders for the payload length
    header_packet[position++] = PLACEHOLDER;

    // Sequence Start
    // header_packet[position++] = SEQUENCE_TAG;    // SEQUENCE tag
    // sequence_start            = position;
    // header_packet[position++] = PLACEHOLDER;    // Placeholder for the sequence length

    // Encoding Username
    header_packet[position++] = UTF8STRING_TAG;    // UTF-8 String tag
    username_length           = strlen(username);
    header_packet[position++] = (unsigned char)username_length;     // Username length is added
    memcpy(&header_packet[position], username, username_length);    // Copy Username to location
    position += username_length;                                    // Go Username length positions forward since we copied

    // Encoding Password
    header_packet[position++] = UTF8STRING_TAG;    // UTF-8 String tag
    password_length           = strlen(password);
    header_packet[position++] = (unsigned char)password_length;     // Password length is added
    memcpy(&header_packet[position], password, password_length);    // Copy Password to location
    position += password_length;                                    // Go Password length positions forward since we copied

    // Replace sequence length placeholder
    // header_packet[sequence_start] = (unsigned char)(position - sequence_start - 1);    // -1 exclude the sequence length byte from sequence length

    // Replace payload length placeholder
    payload_length                   = position - payload_start - 2;                                       // -2 exclude the two payload length bytes from payload length
    header_packet[payload_start]     = (unsigned char)((payload_length >> HIGH_BYTE_SHIFT) & BIT_MASK);    // High byte
    header_packet[payload_start + 1] = (unsigned char)(payload_length & BIT_MASK);                         // Low byte

    printf("\n%d\n\n", sock);
    // Send the encoded packet
    printf("A %02d packet Sent: ", request_type);
    for(unsigned long i = 0; i < sizeof(header_packet) / sizeof(header_packet[0]); i++)
    {
        printf("%02x ", header_packet[i]);
    }
    printf("\n");
    send(sock, header_packet, position, 0);
    printf("A account request has been sent.\n");
}

void account_logout(int sock)
{
    // Header Structure for account request
    unsigned char header_packet[LOGOUT_BUFFER_SIZE];
    unsigned      position = 0;

    // Specify logout packet type
    header_packet[position++] = ACC_LOGOUT;

    // Version
    header_packet[position++] = 0x01;

    // Sender ID
    header_packet[position++] = PLACEHOLDER;
    header_packet[position++] = 0x01;

    // Payload length
    header_packet[position++] = PLACEHOLDER;
    header_packet[position++] = PLACEHOLDER;

    printf("\n%d\n\n", sock);
    // Send the encoded packet
    printf("A %02d packet Sent: ", ACC_LOGOUT);
    for(unsigned long i = 0; i < sizeof(header_packet) / sizeof(header_packet[0]); i++)
    {
        printf("%02x ", header_packet[i]);
    }
    printf("\n");
    send(sock, header_packet, position, 0);
    printf("A logout request has been sent.\n");
}

void account_response(int sock)
{
    unsigned char response[PACKET_BUFFER_SIZE];
    long          bytes_received = recv(sock, response, sizeof(response), 0);
    if(bytes_received == -1)
    {
        perror("Login response was not received");
    }

    // Response type
    if(response[0] == ACC_LOGIN_SUCCESS_TAG)
    {    // ACC_Login_Success Tag
        printf("Login Success, User ID: %d\n", response[LOGIN_RESPONSE_PACKET]);
    }
    else if(response[0] == ACCOUNT_CREATE_SUCCESS)
    {
        printf("Account Creation Success, User ID: %d\n", response[LOGIN_RESPONSE_PACKET]);
    }
    else if(response[0] == SYS_ERROR_TAG)
    {    // SYS_Error Tag
        printf("Login failed, Error Code: %d\n", response[ERROR_RESPONSE_PACKET]);
    }
    else
    {
        printf("An unknown/unaccounted response was received.\n");
    }
}
