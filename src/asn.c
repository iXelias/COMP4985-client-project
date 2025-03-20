#include "asn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Encoding functions
void encode_header(uint8_t *buf, const header_t *header)
{
    header_mark_used(header);
    buf[HEADER_IDX_PACKET_TYPE]      = header->packet_type;
    buf[HEADER_IDX_VERSION]          = header->version;
    buf[HEADER_IDX_SENDER_ID_HIGH]   = (uint8_t)((header->sender_id >> BITS_PER_BYTE) & BYTE_MASK);
    buf[HEADER_IDX_SENDER_ID_LOW]    = (uint8_t)(header->sender_id & BYTE_MASK);
    buf[HEADER_IDX_PAYLOAD_LEN_HIGH] = (uint8_t)((header->payload_len >> BITS_PER_BYTE) & BYTE_MASK);
    buf[HEADER_IDX_PAYLOAD_LEN_LOW]  = (uint8_t)(header->payload_len & BYTE_MASK);
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
    buf[pos] = 1;
    pos++;
    buf[pos] = value;
    pos++;
    return pos;
}

int decode_header(const uint8_t *buf, header_t *header)
{
    header->packet_type = buf[HEADER_IDX_PACKET_TYPE];
    header->version     = buf[HEADER_IDX_VERSION];
    if((header->version == 0) || (header->version > CURRVER))
    {
        fprintf(stderr, "Unsupported protocol version: %d\n", header->version);
        return -1;
    }
    header->sender_id   = (uint16_t)(((uint16_t)buf[HEADER_IDX_SENDER_ID_HIGH] << BITS_PER_BYTE) | ((uint16_t)buf[HEADER_IDX_SENDER_ID_LOW]));
    header->payload_len = (uint16_t)(((uint16_t)buf[HEADER_IDX_PAYLOAD_LEN_HIGH] << BITS_PER_BYTE) | ((uint16_t)buf[HEADER_IDX_PAYLOAD_LEN_LOW]));
    header_mark_used(header);
    return HEADERLEN;
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

int encode_acc_login_req(uint8_t buf[], const char *username, const char *password)
{
    int      pos;
    int      uname_len;
    int      pwd_len;
    int      payload_len;
    header_t header;

    pos         = HEADERLEN;
    uname_len   = (int)strlen(username);
    pwd_len     = (int)strlen(password);
    payload_len = (1 + 1 + uname_len) + (1 + 1 + pwd_len);

    header.packet_type = ACC_Login;
    header.version     = CURRVER;
    header.sender_id   = 0;
    header.payload_len = (uint16_t)payload_len;

    encode_header(buf, &header);
    pos = encode_str(buf, username, pos, ASN_STR);
    pos = encode_str(buf, password, pos, ASN_STR);
    return pos;
}

int encode_acc_logout_req(uint8_t buf[], uint16_t sender_id)
{
    header_t header;

    header.packet_type = ACC_Logout;
    header.version     = CURRVER;
    header.sender_id   = sender_id;
    header.payload_len = 0;

    encode_header(buf, &header);
    return HEADERLEN;
}

int encode_acc_create_req(uint8_t buf[], const char *username, const char *password)
{
    int      pos;
    int      uname_len;
    int      pwd_len;
    int      payload_len;
    header_t header;

    pos         = HEADERLEN;
    uname_len   = (int)strlen(username);
    pwd_len     = (int)strlen(password);
    payload_len = (1 + 1 + uname_len) + (1 + 1 + pwd_len);

    header.packet_type = ACC_Create;
    header.version     = CURRVER;
    header.sender_id   = 0;
    header.payload_len = (uint16_t)payload_len;

    encode_header(buf, &header);
    pos = encode_str(buf, username, pos, ASN_STR);
    pos = encode_str(buf, password, pos, ASN_STR);
    return pos;
}

int encode_chat_send_req(uint8_t buf[], uint16_t sender_id, const char *timestamp, const char *content, const char *username)
{
    int      pos;
    int      ts_len;
    int      content_len;
    int      uname_len;
    int      payload_len;
    header_t header;

    pos         = HEADERLEN;
    ts_len      = (int)strlen(timestamp);
    content_len = (int)strlen(content);
    uname_len   = (int)strlen(username);
    payload_len = (1 + 1 + ts_len) + (1 + 1 + content_len) + (1 + 1 + uname_len);

    header.packet_type = CHT_Send;
    header.version     = CURRVER;
    header.sender_id   = sender_id;
    header.payload_len = (uint16_t)payload_len;

    encode_header(buf, &header);
    pos = encode_str(buf, timestamp, pos, ASN_TIME);
    pos = encode_str(buf, content, pos, ASN_STR);
    pos = encode_str(buf, username, pos, ASN_STR);
    return pos;
}

int encode_lst_get_req(uint8_t buf[], uint16_t sender_id, uint8_t group_id, uint8_t filter)
{
    int      pos;
    int      payload_len;
    header_t header;

    pos         = HEADERLEN;
    payload_len = (1 + 1 + 1) + (1 + 1 + 1);

    header.packet_type = LST_Get;
    header.version     = CURRVER;
    header.sender_id   = sender_id;
    header.payload_len = (uint16_t)payload_len;

    encode_header(buf, &header);
    pos = encode_uint8(buf, group_id, pos, ASN_INT);
    pos = encode_uint8(buf, filter, pos, ASN_ENUM);
    return pos;
}

int encode_client_get_ip(uint8_t buf[])
{
    buf[0] = CLIENT_GetIp;
    buf[1] = CURRVER;
    return 2;
}

// Decoding Functions
int decode_sys_success(const uint8_t buf[], header_t *header, uint8_t *resp_type)
{
    int pos;
    int len;
    pos = decode_header(buf, header);
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
    len = buf[pos];
    pos++;
    if(len != 1)
    {
        fprintf(stderr, "SYS_Success: Unexpected length %d\n", len);
        return -1;
    }
    *resp_type = buf[pos];
    return 0;
}

int decode_acc_login_success(const uint8_t buf[], header_t *header, uint16_t *user_id)
{
    int pos;
    pos = decode_header(buf, header);
    if(header->packet_type != ACC_Login_Success)
    {
        fprintf(stderr, "Expected ACC_Login_Success packet type (0x%02x) but got 0x%02x\n", (unsigned int)ACC_Login_Success, (unsigned int)header->packet_type);
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
        fprintf(stderr, "ACC_Login_Success: Expected INTEGER length of 2, got %d\n", buf[pos]);
        return -1;
    }
    pos++;
    *user_id = (uint16_t)(((uint16_t)buf[pos] << BITS_PER_BYTE) | (uint16_t)buf[pos + 1]);
    return 0;
}

int decode_sys_error(const uint8_t buf[], header_t *header, uint8_t *err_code, char **err_msg)
{
    int pos;
    int len;
    pos = decode_header(buf, header);
    if(buf[pos] != ASN_ENUM)
    {
        fprintf(stderr, "SYS_Error: Expected ENUM tag, got %u\n", buf[pos]);
        return -1;
    }
    pos++;
    len = buf[pos];
    pos++;
    if(len != 1)
    {
        fprintf(stderr, "SYS_Error: Unexpected ENUM length %d\n", len);
        return -1;
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
    int pos;
    pos = decode_header(buf, header);
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
    int pos;
    int count;
    int i;
    pos = decode_header(buf, header);
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
    count = buf[pos];
    pos++;
    *num_users = count;
    *users     = (user_t *)malloc(sizeof(user_t) * (size_t)count);
    if(*users == NULL)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    for(i = 0; i < count; i++)
    {
        if(buf[pos] != ASN_INT)
        {
            fprintf(stderr, "LST_Response: Expected INTEGER tag for user id, got 0x%02x\n", buf[pos]);
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
            fprintf(stderr, "LST_Response: Expected ENUM length of 1 for status, got %d\n", buf[pos]);
            free((*users)[i].username);
            free(*users);
            return -1;
        }
        pos++;
        (*users)[i].status = buf[pos];
        pos++;
        user_mark_used(&((*users)[i]));
    }
    return 0;
}

int decode_manager_return_ip(const uint8_t buf[], int len, int *serverOnline, char **ip, char **port)
{
    int pos;
    (void)len;
    pos = 0;
    if(buf[pos] != MAN_ReturnIp)
    {
        fprintf(stderr, "Expected MAN_ReturnIp, got %u\n", buf[pos]);
        return -1;
    }
    pos++;
    pos++;    // Skip version byte.
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
    return 0;
}
