#ifndef TEST_ASN_H
#define TEST_ASN_H

#include "asn.h"

// Macros for test packet construction
#define DEFAULT_GROUP_ID 5
#define LST_RESPONSE_PAYLOAD_LENGTH 0x14
// These macros are used only in test code.
#define SEQUENCE_TAG 0x30
#define EXPECTED_ENUM_LENGTH 1
#define USERNAME_LEN_USER 4
#define USERNAME_LEN_ADMIN 5

// Utility Function Prototype
void print_hex(const uint8_t *buf, int len);

// Test Function Prototypes
void test_encode_acc_login_req(void);
void test_encode_acc_create_req(void);
void test_decode_sys_success_login(void);
void test_decode_lst_response(void);
void test_encode_chat_send_req_and_decode(void);
void test_encode_lst_get_req(void);
void test_encode_client_get_ip(void);

#endif    // TEST_ASN_H
