#include "asn.h"
#include <arpa/inet.h>    // For htons(), ntohs()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --------------------- */
/*       ENCODING        */
/* --------------------- */

/**
 * @brief Encode the 6-byte header in **network byte order**.
 *        (1 byte packet_type, 1 byte version, 2 bytes sender, 2 bytes payload_len)
 */
void encode_header(uint8_t *buf, const header_t *header)
{
    header_mark_used(header);

    /* 1) Packet type (1 byte) */
    buf[HEADER_IDX_PACKET_TYPE] = header->packet_type;

    /* 2) Version (1 byte) */
    buf[HEADER_IDX_VERSION] = header->version;

    /* 3) Sender ID (2 bytes, big-endian) */
    {
        uint16_t net_sender = htons(header->sender_id);
        memcpy(&buf[HEADER_IDX_SENDER_ID_HIGH], &net_sender, sizeof(uint16_t));
    }

    /* 4) Payload length (2 bytes, big-endian) */
    {
        uint16_t net_len = htons(header->payload_len);
        memcpy(&buf[HEADER_IDX_PAYLOAD_LEN_HIGH], &net_len, sizeof(uint16_t));
    }
}

int encode_str(uint8_t *buf, const char *str, int pos, uint8_t tag)
{
    uint8_t len;
    buf[pos] = tag;
    pos++;
    len      = (uint8_t)strlen(str);
    buf[pos] = len;
    pos++;
    memcpy(&buf[pos], str, (size_t)len);
    pos += len;
    return pos;
}

int encode_uint8(uint8_t *buf, uint8_t value, int pos, uint8_t tag)
{
    buf[pos] = tag;
    pos++;
    buf[pos] = 1;    // length of the 1-byte integer
    pos++;
    buf[pos] = value;
    pos++;
    return pos;
}

/* ACC_Login request: header + 2 UTF8Strings (username, password) */
int encode_acc_login_req(uint8_t *buf, const char *username, const char *password)
{
    int pos;
    int uname_len   = (int)strlen(username);
    int pwd_len     = (int)strlen(password);
    int payload_len = (1 + 1 + uname_len) + (1 + 1 + pwd_len);

    header_t header;
    header.packet_type = ACC_Login;
    header.version     = CURRVER;
    header.sender_id   = 0;    // client doesn't know ID yet
    header.payload_len = (uint16_t)payload_len;

    /* Encode the header in network byte order */
    encode_header(buf, &header);

    /* Now encode the 2 strings in BER TLV format */
    pos = HEADERLEN;    // 6
    pos = encode_str(buf, username, pos, ASN_STR);
    pos = encode_str(buf, password, pos, ASN_STR);
    return pos;
}

int encode_acc_logout_req(uint8_t *buf, uint16_t sender_id)
{
    header_t header;
    header.packet_type = ACC_Logout;
    header.version     = CURRVER;
    header.sender_id   = sender_id;
    header.payload_len = 0;

    encode_header(buf, &header);
    return HEADERLEN;
}

int encode_acc_create_req(uint8_t *buf, const char *username, const char *password)
{
    int pos;
    int uname_len   = (int)strlen(username);
    int pwd_len     = (int)strlen(password);
    int payload_len = (1 + 1 + uname_len) + (1 + 1 + pwd_len);

    header_t header;
    header.packet_type = ACC_Create;
    header.version     = CURRVER;
    header.sender_id   = 0;    // no ID
    header.payload_len = (uint16_t)payload_len;

    encode_header(buf, &header);

    pos = HEADERLEN;
    pos = encode_str(buf, username, pos, ASN_STR);
    pos = encode_str(buf, password, pos, ASN_STR);
    return pos;
}

int encode_chat_send_req(uint8_t *buf, uint16_t sender_id, const char *timestamp, const char *content, const char *username)
{
    int pos;
    int ts_len      = (int)strlen(timestamp);
    int content_len = (int)strlen(content);
    int uname_len   = (int)strlen(username);
    int payload_len = (1 + 1 + ts_len) + (1 + 1 + content_len) + (1 + 1 + uname_len);

    header_t header;
    header.packet_type = CHT_Send;
    header.version     = CURRVER;
    header.sender_id   = sender_id;
    header.payload_len = (uint16_t)payload_len;

    encode_header(buf, &header);

    pos = HEADERLEN;
    pos = encode_str(buf, timestamp, pos, ASN_TIME);
    pos = encode_str(buf, content, pos, ASN_STR);
    pos = encode_str(buf, username, pos, ASN_STR);
    return pos;
}

int encode_lst_get_req(uint8_t *buf, uint16_t sender_id, uint8_t group_id, uint8_t filter)
{
    int pos;
    int payload_len = (1 + 1 + 1) + (1 + 1 + 1);

    header_t header;
    header.packet_type = LST_Get;
    header.version     = CURRVER;
    header.sender_id   = sender_id;
    header.payload_len = (uint16_t)payload_len;

    encode_header(buf, &header);

    pos = HEADERLEN;
    pos = encode_uint8(buf, group_id, pos, ASN_INT);
    pos = encode_uint8(buf, filter, pos, ASN_ENUM);
    return pos;
}

int encode_client_get_ip(uint8_t *buf)
{
    /* Minimal request, no BER payload, just 2 bytes: packet_type, version */
    buf[0] = CLIENT_GetIp;
    buf[1] = CURRVER;
    return 2;
}

/* --------------------- */
/*       DECODING        */
/* --------------------- */

int decode_header(const uint8_t *buf, header_t *header)
{
    /* Match how the server does decode_header(), i.e. 1 byte packet type, 1 byte version, 2 bytes sender, 2 bytes payload len, all big-endian. */

    header->packet_type = buf[HEADER_IDX_PACKET_TYPE];
    header->version     = buf[HEADER_IDX_VERSION];

    /* Convert the next two bytes to sender_id using ntohs */
    {
        uint16_t net_sender_id;
        memcpy(&net_sender_id, &buf[HEADER_IDX_SENDER_ID_HIGH], sizeof(uint16_t));
        header->sender_id = ntohs(net_sender_id);
    }

    /* Convert next two bytes to payload_len using ntohs */
    {
        uint16_t net_len;
        memcpy(&net_len, &buf[HEADER_IDX_PAYLOAD_LEN_HIGH], sizeof(uint16_t));
        header->payload_len = ntohs(net_len);
    }

    /* Optional version check: */
    if((header->version == 0) || (header->version > CURRVER))
    {
        fprintf(stderr, "Unsupported protocol version: %d\n", header->version);
        return -1;
    }

    header_mark_used(header);
    return HEADERLEN;    // 6
}

int decode_utf8_string_tag(const uint8_t buf[], int pos, int expected_tag, char **out)
{
    int len;
    if(buf[pos] != expected_tag)
    {
        fprintf(stderr, "Expected tag %d but got %d\n", expected_tag, buf[pos]);
        return -1;
    }
    pos++;
    len = buf[pos];
    pos++;
    if(len == 0)
    {
        *out = NULL;
        return pos;
    }
    *out = (char *)malloc((size_t)len + 1);
    if(*out == NULL)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memcpy(*out, buf + pos, (size_t)len);
    (*out)[len] = '\0';
    pos += len;
    return pos;
}

/* ----------------------------
   Examples of decode functions
   usage: after decode_header()
   ---------------------------- */

int decode_sys_success(const uint8_t buf[], header_t *header, uint8_t *resp_type)
{
    int pos = decode_header(buf, header);
    if(pos < 0)
    {
        return -1;
    }
    if(buf[pos] != ASN_ENUM)
    {
        fprintf(stderr, "SYS_Success: Expected ENUM tag, got %u\n", buf[pos]);
        return -1;
    }
    pos++;
    {
        int len = buf[pos];
        pos++;
        if(len != 1)
        {
            fprintf(stderr, "SYS_Success: Unexpected length %d\n", len);
            return -1;
        }
    }
    *resp_type = buf[pos];
    return 0;
}

int decode_acc_login_success(const uint8_t buf[], header_t *header, uint16_t *user_id)
{
    int pos = decode_header(buf, header);
    if(pos < 0)
    {
        return -1;
    }
    if(header->packet_type != ACC_Login_Success)
    {
        fprintf(stderr, "Expected ACC_Login_Success (0x%02x) but got 0x%02x\n", (unsigned int)ACC_Login_Success, (unsigned int)header->packet_type);
        return -1;
    }
    if(buf[pos] != ASN_INT)
    {
        fprintf(stderr, "ACC_Login_Success: Expected INTEGER tag, got 0x%02x\n", buf[pos]);
        return -1;
    }
    pos++;
    if(buf[pos] != 0x02)
    {
        fprintf(stderr, "ACC_Login_Success: Expected length=2, got %d\n", buf[pos]);
        return -1;
    }
    pos++;
    *user_id = (uint16_t)((((uint16_t)buf[pos]) << BITS_PER_BYTE) | (uint16_t)buf[pos + 1]);
    return 0;
}

int decode_sys_error(const uint8_t buf[], header_t *header, uint8_t *err_code, char **err_msg)
{
    int pos = decode_header(buf, header);
    if(pos < 0)
    {
        return -1;
    }
    if(buf[pos] != ASN_ENUM)
    {
        fprintf(stderr, "SYS_Error: Expected ENUM tag, got %u\n", buf[pos]);
        return -1;
    }
    pos++;
    {
        int len = buf[pos];
        pos++;
        if(len != 1)
        {
            fprintf(stderr, "SYS_Error: Unexpected ENUM length %d\n", len);
            return -1;
        }
    }
    *err_code = buf[pos];
    pos++;
    pos = decode_utf8_string_tag(buf, pos, ASN_STR, err_msg);
    if(pos < 0)
    {
        return -1;
    }
    return 0;
}

int decode_chat_message(const uint8_t buf[], header_t *header, char **timestamp, char **content, char **username)
{
    int pos = decode_header(buf, header);
    if(pos < 0)
    {
        return -1;
    }
    pos = decode_utf8_string_tag(buf, pos, ASN_TIME, timestamp);
    if(pos < 0)
    {
        return -1;
    }
    pos = decode_utf8_string_tag(buf, pos, ASN_STR, content);
    if(pos < 0)
    {
        return -1;
    }
    pos = decode_utf8_string_tag(buf, pos, ASN_STR, username);
    if(pos < 0)
    {
        return -1;
    }
    return 0;
}

int decode_lst_response(const uint8_t buf[], header_t *header, user_t **users, int *num_users)
{
    int pos = decode_header(buf, header);
    if(pos < 0)
    {
        return -1;
    }
    if(buf[pos] != SEQUENCE_TAG)
    {
        fprintf(stderr, "LST_Response: Expected SEQUENCE tag (0x%02x), got 0x%02x\n", (unsigned int)SEQUENCE_TAG, (unsigned int)buf[pos]);
        return -1;
    }
    pos++;
    {
        int count = buf[pos];
        pos++;
        *num_users = count;
        *users     = (user_t *)malloc(sizeof(user_t) * (size_t)count);
        if(*users == NULL)
        {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        for(int i = 0; i < count; i++)
        {
            if(buf[pos] != ASN_INT)
            {
                fprintf(stderr, "LST_Response: Expected INTEGER tag, got 0x%02x\n", buf[pos]);
                free(*users);
                return -1;
            }
            pos++;
            if(buf[pos] != 0x02)
            {
                fprintf(stderr, "LST_Response: Expected INTEGER length of 2 for user id, got %d\n", buf[pos]);
                free(*users);
                return -1;
            }
            pos++;
            (*users)[i].id = (uint16_t)(((uint16_t)buf[pos] << BITS_PER_BYTE) | ((uint16_t)buf[pos + 1]));
            pos += 2;

            pos = decode_utf8_string_tag(buf, pos, ASN_STR, &((*users)[i].username));
            if(pos < 0)
            {
                free(*users);
                return -1;
            }

            if(buf[pos] != ASN_ENUM)
            {
                fprintf(stderr, "LST_Response: Expected ENUM tag for status, got 0x%02x\n", buf[pos]);
                free((*users)[i].username);
                free(*users);
                return -1;
            }
            pos++;
            if(buf[pos] != EXPECTED_ENUM_LENGTH)
            {
                fprintf(stderr, "LST_Response: Expected ENUM length of 1, got %d\n", buf[pos]);
                free((*users)[i].username);
                free(*users);
                return -1;
            }
            pos++;
            (*users)[i].status = buf[pos];
            pos++;

            user_mark_used(&((*users)[i]));
        }
    }
    return 0;
}

int decode_manager_return_ip(const uint8_t buf[], int len, int *serverOnline, char **ip, char **port)
{
    (void)len; /* We don’t use 'len' since we parse from the buffer start. */
    {
        int pos = 0;
        if(buf[pos] != MAN_ReturnIp)
        {
            fprintf(stderr, "Expected MAN_ReturnIp, got %u\n", buf[pos]);
            return -1;
        }
        pos++;
        pos++;    // skip version
        *serverOnline = buf[pos];
        pos++;

        pos = decode_utf8_string_tag(buf, pos, ASN_STR, ip);
        if(pos < 0)
        {
            return -1;
        }
        pos = decode_utf8_string_tag(buf, pos, ASN_STR, port);
        if(pos < 0)
        {
            return -1;
        }
    }
    return 0;
}
