#include "../include/account.h"
#include "../include/asn.h"
#include "../include/connection.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

/* Keep your macros for max command length, buffer size, etc. */
#define MAX_CMD_LEN 256
#define BUF_SIZE 512

struct networkSocket
{
    int                client_fd;
    struct sockaddr_in address;
};

/* Function prototypes */
static void interactive_loop(int client_fd);
static void handle_server_message(int client_fd);
static void handle_user_command(int client_fd, const char *command_line);

int main(int argc, char *argv[])
{
    struct networkSocket data;
    char                 detected_ip[INET_ADDRSTRLEN];
    char                *manual_address;
    in_port_t            manual_port;

    data.client_fd = 0;
    manual_address = NULL;
    manual_port    = 0;

    /* 1) Parse command-line arguments: -i <ip>, -p <port> */
    parse_args(argc, argv, &manual_address, &manual_port);

    /* 2) If no address was specified, detect it */
    if(manual_address == NULL)
    {
        in_addr_t ip;
        find_address(&ip, detected_ip);
        manual_address = detected_ip;
    }

    /* 3) If no port was specified, error */
    if(manual_port == 0)
    {
        usage(argv[0], EXIT_FAILURE, "Error: Empty Port");
    }

    /* 4) Connect to the server */
    data.client_fd = setup_client(&data.address, manual_address, manual_port);
    if(data.client_fd < 0)
    {
        exit(EXIT_FAILURE);
    }

    display_port(&data.address, manual_address);

    /* 5) Switch to interactive loop mode */
    printf("Client starting.\n");
    printf("Type commands like:\n");
    printf("  create <username> <password>\n");
    printf("  login <username> <password>\n");
    printf("  logout\n");
    printf("  chat <message>\n");
    printf("  quit or exit\n");
    interactive_loop(data.client_fd);

    close(data.client_fd);
    return EXIT_SUCCESS;
}

/**
 * @brief Continuously listen for user input (stdin) and server messages (socket).
 *        We'll use select() on both.
 */
static void interactive_loop(int client_fd)
{
    while(1)
    {
        fd_set readfds;
        int    max_fd;
        int    ret;

        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(client_fd, &readfds);

        max_fd = (STDIN_FILENO > client_fd) ? STDIN_FILENO : client_fd;

        /* Wait for user input or server data */
        ret = select(max_fd + 1, &readfds, NULL, NULL, NULL);
        if(ret < 0)
        {
            if(errno == EINTR)
            {
                /* Interrupted by signal, keep going */
                continue;
            }
            perror("select");
            break;
        }

        /* 1) Check user input on stdin */
        if(FD_ISSET(STDIN_FILENO, &readfds))
        {
            char   command_line[MAX_CMD_LEN];
            size_t line_len;

            memset(command_line, 0, sizeof(command_line));
            if(!fgets(command_line, sizeof(command_line), stdin))
            {
                /* EOF on stdin or error */
                printf("User input closed.\n");
                break;
            }

            /* Remove trailing newline */
            line_len = strlen(command_line);
            if(line_len > 0 && command_line[line_len - 1] == '\n')
            {
                command_line[line_len - 1] = '\0';
            }

            /* If user typed "quit" or "exit", break */
            if(strcmp(command_line, "quit") == 0 || strcmp(command_line, "exit") == 0)
            {
                printf("Client closing.\n");
                break;
            }

            /* Otherwise handle user command */
            handle_user_command(client_fd, command_line);
        }

        /* 2) Check if server sent data */
        if(FD_ISSET(client_fd, &readfds))
        {
            handle_server_message(client_fd);
        }
    }
}

/**
 * @brief Reads one packet from the server, decodes it, prints info
 */
static void handle_server_message(int client_fd)
{
    uint8_t  header_buf[HEADERLEN];
    ssize_t  bytes_read;
    header_t header;
    uint8_t *packet_buf; /* Declare at top for ISO C90 */

    /* Read the 6-byte header first */
    bytes_read = read(client_fd, header_buf, HEADERLEN);
    if(bytes_read == 0)
    {
        printf("Server closed connection.\n");
        exit(EXIT_SUCCESS);
    }
    else if(bytes_read < 0)
    {
        perror("read header");
        exit(EXIT_FAILURE);
    }
    else if(bytes_read < HEADERLEN)
    {
        fprintf(stderr, "Partial header: %zd < %d\n", bytes_read, HEADERLEN);
        exit(EXIT_FAILURE);
    }

    /* Decode just the 6-byte header */
    if(decode_header(header_buf, &header) < 0)
    {
        fprintf(stderr, "Invalid or unsupported header.\n");
        return;
    }

    /* If there's no payload, we can stop here */
    if(header.payload_len == 0)
    {
        printf("Received packet type 0x%02X with no payload.\n", header.packet_type);
        return;
    }

    /* Fix sign-conversion: cast header.payload_len to size_t */
    packet_buf = (uint8_t *)malloc((size_t)header.payload_len + HEADERLEN);
    if(!packet_buf)
    {
        perror("malloc");
        return;
    }

    memcpy(packet_buf, header_buf, HEADERLEN);

    /* Read the payload into packet_buf right after the header */
    {
        ssize_t payload_read = read(client_fd, packet_buf + HEADERLEN, header.payload_len);
        if(payload_read < 0)
        {
            perror("read payload");
            free(packet_buf);
            return;
        }
        if((size_t)payload_read < header.payload_len)
        {
            fprintf(stderr, "Partial payload: %zd < %u\n", payload_read, header.payload_len);
            free(packet_buf);
            return;
        }
    }

    /* Switch on packet_type, decode with decode_*() passing packet_buf */
    switch(header.packet_type)
    {
        case SYS_Success:
        {
            uint8_t resp_type;
            if(decode_sys_success(packet_buf, &header, &resp_type) == 0)
            {
                printf("[Server->Client] SYS_Success: responding to packet type %u\n", resp_type);
            }
            else
            {
                printf("Error decoding SYS_Success\n");
            }
            break;
        }
        case SYS_Error:
        {
            uint8_t err_code;
            char   *err_msg = NULL;
            if(decode_sys_error(packet_buf, &header, &err_code, &err_msg) == 0)
            {
                printf("[Server->Client] SYS_Error: code = %u, msg = %s\n", err_code, err_msg);
                free(err_msg);
            }
            else
            {
                printf("Error decoding SYS_Error\n");
            }
            break;
        }
        case ACC_Login_Success:
        {
            uint16_t user_id;
            if(decode_acc_login_success(packet_buf, &header, &user_id) == 0)
            {
                printf("[Server->Client] ACC_Login_Success: user ID = %u\n", user_id);
            }
            else
            {
                printf("Error decoding ACC_Login_Success\n");
            }
            break;
        }
        case CHT_Send:
        {
            char *timestamp = NULL;
            char *content   = NULL;
            char *username  = NULL;
            if(decode_chat_message(packet_buf, &header, &timestamp, &content, &username) == 0)
            {
                printf("[Server->Client] Chat Message:\n"
                       "  Timestamp: %s\n"
                       "  Content: %s\n"
                       "  Username: %s\n",
                       timestamp,
                       content,
                       username);
                free(timestamp);
                free(content);
                free(username);
            }
            else
            {
                printf("Error decoding chat message\n");
            }
            break;
        }
        default:
            printf("Unhandled packet type: 0x%02X\n", header.packet_type);
            break;
    }

    free(packet_buf);
}

/**
 * @brief Takes a user command (create/login/logout/chat) and sends the corresponding packet
 */
static void handle_user_command(int client_fd, const char *command_line)
{
    char        cmd_copy[MAX_CMD_LEN];
    char       *saveptr;
    const char *token;
    size_t      len_cmd_copy;
    uint8_t     buf[BUF_SIZE];

    memset(cmd_copy, 0, sizeof(cmd_copy));
    len_cmd_copy = sizeof(cmd_copy) - 1;
    strncpy(cmd_copy, command_line, len_cmd_copy);
    cmd_copy[len_cmd_copy] = '\0';

    /* use strtok_r for reentrancy */
    saveptr = NULL;
    token   = strtok_r(cmd_copy, " ", &saveptr);
    if(!token)
    {
        return;
    }

    /* parse commands */
    if(strcmp(token, "create") == 0)
    {
        /* create <username> <password> */
        const char *uname = strtok_r(NULL, " ", &saveptr);
        const char *pass  = strtok_r(NULL, " ", &saveptr);
        if(!uname || !pass)
        {
            printf("Usage: create <username> <password>\n");
            return;
        }
        {
            int packet_len = encode_acc_create_req(buf, uname, pass);
            if(write(client_fd, buf, (size_t)packet_len) < 0)
            {
                perror("write create");
            }
        }
    }
    else if(strcmp(token, "login") == 0)
    {
        /* login <username> <password> */
        const char *uname = strtok_r(NULL, " ", &saveptr);
        const char *pass  = strtok_r(NULL, " ", &saveptr);
        if(!uname || !pass)
        {
            printf("Usage: login <username> <password>\n");
            return;
        }
        {
            int packet_len = encode_acc_login_req(buf, uname, pass);
            if(write(client_fd, buf, (size_t)packet_len) < 0)
            {
                perror("write login");
            }
        }
    }
    else if(strcmp(token, "logout") == 0)
    {
        /* logout */
        {
            /* e.g. sender_id = 1 for demonstration */
            int packet_len = encode_acc_logout_req(buf, 1);
            if(write(client_fd, buf, (size_t)packet_len) < 0)
            {
                perror("write logout");
            }
        }
    }
    else if(strcmp(token, "chat") == 0)
    {
        /* chat <message> */
        const char *chat_msg = strtok_r(NULL, "", &saveptr);
        if(!chat_msg)
        {
            printf("Usage: chat <message>\n");
            return;
        }
        {
            const char *timestamp  = "20250304160000Z";
            const char *username   = "You";
            int         packet_len = encode_chat_send_req(buf, 1, timestamp, chat_msg, username);
            if(write(client_fd, buf, (size_t)packet_len) < 0)
            {
                perror("write chat");
            }
        }
    }
    else
    {
        printf("Unrecognized command: %s\n", token);
        printf("Commands:\n");
        printf("  create <username> <password>\n");
        printf("  login <username> <password>\n");
        printf("  logout\n");
        printf("  chat <message>\n");
        printf("  quit or exit\n");
    }
}
