#ifndef ASN_H
#define ASN_H

#ifdef __cplusplus
    #include <cstdint>
extern "C"
{
#else
    #include <stdint.h>
#endif

// Protocol Constants
#define HEADERLEN 6
#define CURRVER 0x03    // Protocol Version 3

// Packet Types
#define SYS_Success 0x00
#define SYS_Error 0x01
#define ACC_Login 0x0A
#define ACC_Login_Success 0x0B    // ACC_Login_Success includes the user ID.
#define ACC_Logout 0x0C
#define ACC_Create 0x0D
#define ACC_Edit 0x0E
#define CHT_Send 0x14
#define LST_Get 0x1E
#define LST_Response 0x1F

// Client Connection Protocol Packet Types
#define CLIENT_GetIp 0x00
#define MAN_ReturnIp 0x01

// BER Tags for TLV Encoding
#define ASN_STR 0x0C     // UTF8String
#define ASN_TIME 0x18    // Generalized Time (YYYYMMDDhhmmssZ)
#define ASN_INT 0x02     // INTEGER
#define ASN_ENUM 0x0A    // ENUMERATED

// Additional Constants for LST_Response
#define SEQUENCE_TAG 0x30         // Used to denote a SEQUENCE in BER encoding
#define EXPECTED_ENUM_LENGTH 1    // Expected length for ENUMERATED fields

// Bit and Byte Constants
#define BITS_PER_BYTE 8
#define BYTE_MASK 0xFF

// Header Field Indexes (for the 6-byte header)
#define HEADER_IDX_PACKET_TYPE 0
#define HEADER_IDX_VERSION 1
#define HEADER_IDX_SENDER_ID_HIGH 2
#define HEADER_IDX_SENDER_ID_LOW 3
#define HEADER_IDX_PAYLOAD_LEN_HIGH 4
#define HEADER_IDX_PAYLOAD_LEN_LOW 5

    // Header Structure (6 bytes)
    // This structure holds the header values required by the protocol.
    // Even if not all members are referenced outside this module, they are
    // essential for packet encoding/decoding.
    typedef struct
    {
        uint8_t  packet_type;
        uint8_t  version;
        uint16_t sender_id;
        uint16_t payload_len;
    } header_t;

    // Dummy inline function to mark header_t members as used.
    static inline void header_mark_used(const header_t *h)
    {
        (void)h->packet_type;
        (void)h->version;
        (void)h->sender_id;
        (void)h->payload_len;
    }

    // User Structure (for LST_Response)
    typedef struct
    {
        uint16_t id;
        char    *username;    // allocated string
        uint8_t  status;      // offline (0), online (1), busy (2)
    } user_t;

    // Dummy inline function to mark user_t members as used.
    static inline void user_mark_used(const user_t *u)
    {
        (void)u->id;
        (void)u->username;
        (void)u->status;
    }

    // Encoding Functions
    int encode_acc_login_req(uint8_t buf[], const char *username, const char *password);
    int encode_acc_logout_req(uint8_t buf[], uint16_t sender_id);
    int encode_acc_create_req(uint8_t buf[], const char *username, const char *password);
    int encode_chat_send_req(uint8_t buf[], uint16_t sender_id, const char *timestamp, const char *content, const char *username);
    int encode_lst_get_req(uint8_t buf[], uint16_t sender_id, uint8_t group_id, uint8_t filter);
    int encode_client_get_ip(uint8_t buf[]);

    // Decoding Functions
    int decode_sys_success(const uint8_t buf[], header_t *header, uint8_t *resp_type);
    int decode_acc_login_success(const uint8_t buf[], header_t *header, uint16_t *user_id);
    int decode_sys_error(const uint8_t buf[], header_t *header, uint8_t *err_code, char **err_msg);
    int decode_chat_message(const uint8_t buf[], header_t *header, char **timestamp, char **content, char **username);
    int decode_lst_response(const uint8_t buf[], header_t *header, user_t **users, int *num_users);
    int decode_manager_return_ip(const uint8_t buf[], int len, int *serverOnline, char **ip, char **port);

    // Internal Helper Function Prototypes
    void encode_header(uint8_t *buf, const header_t *header);
    int  encode_str(uint8_t *buf, const char *str, int pos, uint8_t tag);
    int  encode_uint8(uint8_t *buf, uint8_t value, int pos, uint8_t tag);
    int  decode_utf8_string_tag(const uint8_t buf[], int pos, int expected_tag, char **out);
    int  decode_header(const uint8_t *buf, header_t *header);

#ifdef __cplusplus
}
#endif

#endif    // ASN_H
