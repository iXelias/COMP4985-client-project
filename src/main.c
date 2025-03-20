#include "../include/asn.h"
#include "../include/connection.h"
#include "../include/ncurses_gui.h"
#include <arpa/inet.h>
#include <errno.h>
#include <ncurses.h>
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
static void interactive_loop(int client_fd, GuiData gui_data);
static void handle_server_message(int client_fd, GuiData gui_data);
static void handle_user_command(int client_fd, const char *command_line, GuiData gui_data);
void log_error(GuiData *gui_data, const char *message);

int main(int argc, char *argv[])
{
    struct networkSocket data;
    char                 detected_ip[INET_ADDRSTRLEN];
    char                *manual_address;
    in_port_t            manual_port;
    GuiData              gui_data;

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
    init_gui(&gui_data);
    add_message_to_chat(&gui_data, "Client starting.\n");
    add_message_to_chat(&gui_data, "Type commands like:\n");
    add_message_to_chat(&gui_data, "  create <username> <password>\n");
    add_message_to_chat(&gui_data, "  login <username> <password>\n");
    add_message_to_chat(&gui_data, "  logout\n");
    add_message_to_chat(&gui_data, "  chat <message>\n");
    add_message_to_chat(&gui_data, "  quit or exit\n");
    add_message_to_chat(&gui_data, "Client starting.\n");
    interactive_loop(data.client_fd, gui_data);

    close(data.client_fd);
    return EXIT_SUCCESS;
}

/**
 * @brief Continuously listen for user input (stdin) and server messages (socket).
 *        We'll use select() on both.
 */
static void interactive_loop(int client_fd, GuiData gui_data) {
    char input_buffer[MAX_CMD_LEN];

    while (1) {
        fd_set readfds;
        int max_fd;
        int ret;

        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(client_fd, &readfds);

        max_fd = (STDIN_FILENO > client_fd) ? STDIN_FILENO : client_fd;

        // Wait for user input or server data
        ret = select(max_fd + 1, &readfds, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR) {
                // Interrupted by signal, keep going
                continue;
            }
            perror("select");
            break;
        }

        // Check user input on stdin
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            // Use the new input function to get user input
            get_user_input(&gui_data, input_buffer, sizeof(input_buffer));

            // Handle the user command
            if (strcmp(input_buffer, "quit") == 0 || strcmp(input_buffer, "exit") == 0) {
                printf("Client closing.\n");
                break;
            }

            handle_user_command(client_fd, input_buffer, gui_data);
        }

        // Check if server sent data
        if (FD_ISSET(client_fd, &readfds)) {
            handle_server_message(client_fd, gui_data);
        }
    }

    cleanup_gui(&gui_data);
}

/**
 * @brief Reads one packet from the server, decodes it, prints info
 */
static void handle_server_message(int client_fd, GuiData gui_data)
{
    uint8_t  header_buf[HEADERLEN];
    ssize_t  bytes_read;
    header_t header;
    uint8_t *packet_buf; /* Declare at top for ISO C90 */

    /* Read the 6-byte header first */
    bytes_read = read(client_fd, header_buf, HEADERLEN);
    if(bytes_read == 0)
    {
        add_message_to_chat(&gui_data, "Server closed connection.\n");
        exit(EXIT_SUCCESS);
    }
    else if(bytes_read < 0)
    {
        log_error(&gui_data, "read header");
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
        char chat_message[BUF_SIZE];
        snprintf(chat_message, sizeof(chat_message), "Received packet type 0x%02x with no payload.\n", header.packet_type);

        add_message_to_chat(&gui_data, chat_message);
        return;
    }

    /* Fix sign-conversion: cast header.payload_len to size_t */
    packet_buf = (uint8_t *)malloc((size_t)header.payload_len + HEADERLEN);
    if(!packet_buf)
    {
        log_error(&gui_data, "malloc");
        return;
    }

    memcpy(packet_buf, header_buf, HEADERLEN);

    /* Read the payload into packet_buf right after the header */
    {
        ssize_t payload_read = read(client_fd, packet_buf + HEADERLEN, header.payload_len);
        if(payload_read < 0)
        {
            log_error(&gui_data, "read payload");
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
                char chat_message[BUF_SIZE];
                snprintf(chat_message, sizeof(chat_message), "[Server->Client] SYS_Success: responding to packet type %u\n", resp_type);
                add_message_to_chat(&gui_data, chat_message);
            }
            else
            {
                log_error(&gui_data, "Error decoding SYS_Success\n");
            }
            break;
        }
        case SYS_Error:
        {
            uint8_t err_code;
            char   *err_msg = NULL;
            if(decode_sys_error(packet_buf, &header, &err_code, &err_msg) == 0)
            {
                char chat_message[BUF_SIZE];
                snprintf(chat_message, sizeof(chat_message), "[Server->Client] SYS_Error: code = %u, msg = %s\n", err_code, err_msg);
                add_message_to_chat(&gui_data, chat_message);
                free(err_msg);
            }
            else
            {
                log_error(&gui_data, "Error decoding SYS_Error\n");
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
                char chat_message[BUF_SIZE];
                snprintf(chat_message, sizeof(chat_message), "[%s] %s: %s", timestamp, username, content);

                add_message_to_chat(&gui_data, chat_message);

                // Print to console for debugging
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
static void handle_user_command(int client_fd, const char *command_line, GuiData gui_data)
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
            add_message_to_chat(&gui_data, "Usage: create <username> <password>\n");
            return;
        }
        {
            int packet_len = encode_acc_create_req(buf, uname, pass);
            if(write(client_fd, buf, (size_t)packet_len) < 0)
            {
                log_error(&gui_data, "write create");
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
            add_message_to_chat(&gui_data, "Usage: login <username> <password>\n");
            return;
        }
        {
            int packet_len = encode_acc_login_req(buf, uname, pass);
            if(write(client_fd, buf, (size_t)packet_len) < 0)
            {
                log_error(&gui_data, "write login");
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
                log_error(&gui_data, "write logout");
            }
        }
    }
    else if(strcmp(token, "chat") == 0)
    {
        /* chat <message> */
        const char *chat_msg = strtok_r(NULL, "", &saveptr);
        if(!chat_msg)
        {
            add_message_to_chat(&gui_data, "Usage: chat <message>\n");
            return;
        }
        {
            const char *timestamp  = "20250304160000Z";
            const char *username   = "You";
            int         packet_len = encode_chat_send_req(buf, 1, timestamp, chat_msg, username);
            if(write(client_fd, buf, (size_t)packet_len) < 0)
            {
                log_error(&gui_data, "write chat");
            }
        }
    }
    else
    {
        char error_message[BUF_SIZE];  // Buffer to hold formatted message
        snprintf(error_message, sizeof(error_message), "Unrecognized command: %s", token);
        add_message_to_chat(&gui_data, error_message);
        add_message_to_chat(&gui_data, "Commands:\n");
        add_message_to_chat(&gui_data, "  create <username> <password>\n");
        add_message_to_chat(&gui_data, "  login <username> <password>\n");
        add_message_to_chat(&gui_data, "  logout\n");
        add_message_to_chat(&gui_data, "  chat <message>\n");
        add_message_to_chat(&gui_data, "  quit or exit\n");
    }
}

void log_error(GuiData *gui_data, const char *message) {
    // Log the error to the terminal using perror
    perror(message);

    // Log the error to the chat box
    char error_message[BUF_SIZE];
    snprintf(error_message, sizeof(error_message), "Error: %s: %s", message, strerror(errno));
    add_message_to_chat(gui_data, error_message);
}
