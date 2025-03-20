#include "test_asn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_BUFFER_SIZE 256

// Utility: Print a Buffer in Hexadecimal
void print_hex(const uint8_t *buf, int len)
{
    int i;
    for(i = 0; i < len; i++)
    {
        printf("%02x ", buf[i]);
    }
    printf("\n");
}

void test_encode_acc_login_req(void)
{
    uint8_t     buffer[TEST_BUFFER_SIZE];
    int         pos;
    const char *username;
    const char *password;

    username = "TESTINGTESTINGTESTINGTESTINGTESTINGTESTINGTESTING";
    password = "SUPERSECRETPASSWORD";

    pos = encode_acc_login_req(buffer, username, password);
    printf("Encoded ACC_Login Request (%d bytes):\n", pos);
    print_hex(buffer, pos);
}

void test_encode_acc_create_req(void)
{
    uint8_t     buffer[TEST_BUFFER_SIZE];
    int         pos;
    const char *username;
    const char *password;

    username = "CREATINGANACCOUNT";
    password = "NEWPASSWORD";

    pos = encode_acc_create_req(buffer, username, password);
    printf("\nEncoded ACC_Create Request (%d bytes):\n", pos);
    print_hex(buffer, pos);
}

void test_decode_sys_success_login(void)
{
    /*
       Example: a successful login response with ACC_Login_Success.
       Header: ACC_Login_Success (0x0B), Version 3, Sender ID 0, Payload length 4
       Payload: 0x02, 0x02, 0x00, 0x01 (INTEGER tag, length 2, value 0x0001)
    */
    uint8_t login_success_buf[] = {
        ACC_Login_Success,
        0x03,
        0x00,
        0x00,
        0x00,
        0x04,    // Header
        0x02,
        0x02,
        0x00,
        0x01    // Payload
    };
    header_t header;
    uint16_t user_id;
    user_id = 0;
    if(decode_acc_login_success(login_success_buf, &header, &user_id) == 0)
    {
        printf("\nDecoded ACC_Login_Success:\n");
        printf("User ID: %d\n", user_id);
    }
    else
    {
        printf("Failed to decode ACC_Login_Success response.\n");
    }
}

void test_decode_lst_response(void)
{
    uint8_t lst_response_buf[] = {
        LST_Response,
        0x03,
        0x00,
        0x01,
        0x00,
        LST_RESPONSE_PAYLOAD_LENGTH,
        SEQUENCE_TAG,
        0x02,    // SEQUENCE tag and count (2 users)
        // User 1:
        ASN_INT,
        0x02,
        0x00,
        0x01,    // INTEGER (User ID = 1)
        ASN_STR,
        USERNAME_LEN_USER,
        'U',
        's',
        'e',
        'r',    // UTF8String "User"
        ASN_ENUM,
        EXPECTED_ENUM_LENGTH,
        0x01,    // ENUMERATED status = 1
        // User 2:
        ASN_INT,
        0x02,
        0x00,
        0x02,    // INTEGER (User ID = 2)
        ASN_STR,
        USERNAME_LEN_ADMIN,
        'A',
        'd',
        'm',
        'i',
        'n',    // UTF8String "Admin"
        ASN_ENUM,
        EXPECTED_ENUM_LENGTH,
        0x02    // ENUMERATED status = 2
    };
    header_t header;
    user_t  *users;
    int      num_users;

    users     = NULL;
    num_users = 0;
    if(decode_lst_response(lst_response_buf, &header, &users, &num_users) == 0)
    {
        printf("\nDecoded LST_Response:\n");
        printf("Number of users: %d\n", num_users);
        {
            int j;
            for(j = 0; j < num_users; j++)
            {
                printf("User %d: ID = %d, Username = %s, Status = %d\n", j + 1, users[j].id, users[j].username, users[j].status);
                free(users[j].username);
            }
        }
        free(users);
    }
    else
    {
        printf("Failed to decode LST_Response.\n");
    }
}

void test_encode_chat_send_req_and_decode(void)
{
    uint8_t     buffer[TEST_BUFFER_SIZE];
    int         pos;
    header_t    header;
    const char *timestamp;
    const char *content;
    const char *chat_user;
    char       *dec_timestamp;
    char       *dec_content;
    char       *dec_username;

    timestamp     = "20240301123045Z";
    content       = "THIS IS A TEST LOREM IPSUM!@#$%^&*()_+";
    chat_user     = "DARCYUSER";
    dec_timestamp = NULL;
    dec_content   = NULL;
    dec_username  = NULL;

    pos = encode_chat_send_req(buffer, 1, timestamp, content, chat_user);
    printf("\nEncoded Chat Send Request (%d bytes):\n", pos);
    print_hex(buffer, pos);

    if(decode_chat_message(buffer, &header, &dec_timestamp, &dec_content, &dec_username) == 0)
    {
        printf("\nDecoded Chat Message:\n");
        printf("Timestamp: %s\n", dec_timestamp);
        printf("Content: %s\n", dec_content);
        printf("Username: %s\n", dec_username);
    }
    else
    {
        printf("Failed to decode chat message.\n");
    }
    free(dec_timestamp);
    free(dec_content);
    free(dec_username);
}

void test_encode_lst_get_req(void)
{
    uint8_t buffer[TEST_BUFFER_SIZE];
    int     pos;
    pos = encode_lst_get_req(buffer, 1, DEFAULT_GROUP_ID, 1);
    printf("\nEncoded LST_Get Request (%d bytes):\n", pos);
    print_hex(buffer, pos);
}

void test_encode_client_get_ip(void)
{
    uint8_t buffer[TEST_BUFFER_SIZE];
    int     pos;
    pos = encode_client_get_ip(buffer);
    printf("\nEncoded CLIENT_GetIp Request (%d bytes):\n", pos);
    print_hex(buffer, pos);
}

int main(void)
{
    test_encode_acc_login_req();
    test_encode_acc_create_req();
    test_decode_sys_success_login();
    test_decode_lst_response();
    test_encode_chat_send_req_and_decode();
    test_encode_lst_get_req();
    test_encode_client_get_ip();
    return 0;
}
