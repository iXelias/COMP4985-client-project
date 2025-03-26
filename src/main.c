#include "../include/asn.h"
#include "../include/connection.h"
#include "../include/ncurses_gui.h"
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Keep your macros for max command length, buffer size, etc. */
#define BUF_SIZE 512
#define MAX_CMD_LEN 256
#define TIMESTAMP_SIZE 32

struct networkSocket
{
    int                client_fd;
    struct sockaddr_in address;
};

/* Function prototypes (now taking GuiData pointers) */
static void interactive_loop(int client_fd, GuiData *gui_data);
static void handle_server_message(int client_fd, GuiData *gui_data);
static void handle_user_command(int client_fd, const char *command_line, GuiData *gui_data);
void        log_error(GuiData *gui_data, const char *message);

int main(int argc, char *argv[])
{
    struct networkSocket data;
    char                *manual_address;
    char                 detected_ip[INET_ADDRSTRLEN];
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
    gui_data.logged_in           = 0;
    gui_data.current_username[0] = '\0';
    add_message_to_chat(&gui_data, "Client starting.\n");
    add_message_to_chat(&gui_data, "Type commands like:\n");
    add_message_to_chat(&gui_data, "  /create <username> <password>\n");
    add_message_to_chat(&gui_data, "  /login <username> <password>\n");
    add_message_to_chat(&gui_data, "  /logout\n");
    add_message_to_chat(&gui_data, "  /quit or /exit\n");
    add_message_to_chat(&gui_data, "Client starting.\n");

    interactive_loop(data.client_fd, &gui_data);

    close(data.client_fd);
    return EXIT_SUCCESS;
}

/**
 * @brief Continuously listen for user input (stdin) and server messages (socket).
 *        Uses select() to wait on both descriptors.
 */
static void interactive_loop(int client_fd, GuiData *gui_data)
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

        ret = select(max_fd + 1, &readfds, NULL, NULL, NULL);
        if(ret < 0)
        {
            if(errno == EINTR)
            {
                continue;
            }
            perror("select");
            break;
        }

        if(FD_ISSET(STDIN_FILENO, &readfds))
        {
            char input_buffer[MAX_CMD_LEN];
            get_user_input(gui_data, input_buffer, sizeof(input_buffer));

            /* Check for quit command */
            if(strcmp(input_buffer, "/quit") == 0 || strcmp(input_buffer, "/exit") == 0)
            {
                printf("Client closing.\n");
                break;
            }

            /* Process commands (starting with '/') or chat messages */
            if(input_buffer[0] == '/')
            {
                handle_user_command(client_fd, input_buffer, gui_data);
            }
            else
            {
                if(!gui_data->logged_in)
                {
                    add_message_to_chat(gui_data, "You must log in before sending chat messages.\n");
                }
                else
                {
                    uint8_t          buf[BUF_SIZE];
                    time_t           now;
                    const struct tm *tm_info;
                    struct tm        tm_result;
                    char             timestamp[TIMESTAMP_SIZE];
                    int              packet_len;

                    now     = time(NULL);
                    tm_info = gmtime_r(&now, &tm_result);
                    strftime(timestamp, sizeof(timestamp), "%Y%m%d%H%M%SZ", tm_info);

                    packet_len = encode_chat_send_req(buf, 1, timestamp, input_buffer, gui_data->current_username);
                    if(write(client_fd, buf, (size_t)packet_len) < 0)
                    {
                        log_error(gui_data, "write chat");
                    }
                }
            }
        }

        if(FD_ISSET(client_fd, &readfds))
        {
            handle_server_message(client_fd, gui_data);
        }
    }

    cleanup_gui(gui_data);
}

/**
 * @brief Reads one packet from the server, decodes it, and processes the data.
 */
static void handle_server_message(int client_fd, GuiData *gui_data)
{
    uint8_t  header_buf[HEADERLEN];
    ssize_t  bytes_read;
    header_t header;
    uint8_t *packet_buf;

    bytes_read = read(client_fd, header_buf, HEADERLEN);
    if(bytes_read == 0)
    {
        add_message_to_chat(gui_data, "Server closed connection.\n");
        exit(EXIT_SUCCESS);
    }
    else if(bytes_read < 0)
    {
        log_error(gui_data, "read header");
        exit(EXIT_FAILURE);
    }
    else if(bytes_read < HEADERLEN)
    {
        fprintf(stderr, "Partial header: %zd < %d\n", bytes_read, HEADERLEN);
        exit(EXIT_FAILURE);
    }

    if(decode_header(header_buf, &header) < 0)
    {
        fprintf(stderr, "Invalid or unsupported header.\n");
        return;
    }

    if(header.payload_len == 0)
    {
        char chat_message[BUF_SIZE];
        snprintf(chat_message, sizeof(chat_message), "Received packet type 0x%02x with no payload.\n", header.packet_type);
        add_message_to_chat(gui_data, chat_message);
        return;
    }

    packet_buf = (uint8_t *)malloc((size_t)header.payload_len + HEADERLEN);
    if(!packet_buf)
    {
        log_error(gui_data, "malloc");
        return;
    }

    memcpy(packet_buf, header_buf, HEADERLEN);

    {
        ssize_t payload_read = read(client_fd, packet_buf + HEADERLEN, header.payload_len);
        if(payload_read < 0)
        {
            log_error(gui_data, "read payload");
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

    switch(header.packet_type)
    {
        case SYS_Success:
        {
            uint8_t resp_type;
            if(decode_sys_success(packet_buf, &header, &resp_type) == 0)
            {
                char chat_message[BUF_SIZE];
                snprintf(chat_message, sizeof(chat_message), "[Server->Client] SYS_Success: responding to packet type %u\n", resp_type);
                add_message_to_chat(gui_data, chat_message);
            }
            else
            {
                log_error(gui_data, "Error decoding SYS_Success\n");
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
                add_message_to_chat(gui_data, chat_message);
                free(err_msg);
            }
            else
            {
                log_error(gui_data, "Error decoding SYS_Error\n");
            }
            break;
        }
        case ACC_Login_Success:
        {
            uint16_t user_id;
            if(decode_acc_login_success(packet_buf, &header, &user_id) == 0)
            {
                char chat_message[BUF_SIZE];
                snprintf(chat_message, sizeof(chat_message), "[Server->Client] ACC_Login_Success: user ID = %u\n", user_id);
                add_message_to_chat(gui_data, chat_message);
                gui_data->logged_in = 1;
            }
            else
            {
                log_error(gui_data, "Error decoding ACC_Login_Success\n");
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
                add_message_to_chat(gui_data, chat_message);
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
 * @brief Parses and processes a user command, such as /create, /login, or /logout.
 */
static void handle_user_command(int client_fd, const char *command_line, GuiData *gui_data)
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

    token = strtok_r(cmd_copy, " ", &saveptr);
    if(!token)
    {
        return;
    }

    if(strcmp(token, "/create") == 0)
    {
        int         packet_len;
        const char *uname = strtok_r(NULL, " ", &saveptr);
        const char *pass  = strtok_r(NULL, " ", &saveptr);

        if(!uname || !pass)
        {
            add_message_to_chat(gui_data, "Usage: /create <username> <password>\n");
            return;
        }

        packet_len = encode_acc_create_req(buf, uname, pass);
        if(write(client_fd, buf, (size_t)packet_len) < 0)
        {
            log_error(gui_data, "write create");
        }
    }
    else if(strcmp(token, "/login") == 0)
    {
        int         packet_len;
        const char *uname = strtok_r(NULL, " ", &saveptr);
        const char *pass  = strtok_r(NULL, " ", &saveptr);

        if(!uname || !pass)
        {
            add_message_to_chat(gui_data, "Usage: /login <username> <password>\n");
            return;
        }

        /* Save the username in gui_data */
        strncpy(gui_data->current_username, uname, MAX_USERNAME_LEN - 1);
        gui_data->current_username[MAX_USERNAME_LEN - 1] = '\0';

        packet_len = encode_acc_login_req(buf, uname, pass);
        if(write(client_fd, buf, (size_t)packet_len) < 0)
        {
            log_error(gui_data, "write login");
        }
    }
    else if(strcmp(token, "/logout") == 0)
    {
        int packet_len = encode_acc_logout_req(buf, 1);
        if(write(client_fd, buf, (size_t)packet_len) < 0)
        {
            log_error(gui_data, "write logout");
        }
    }
    else
    {
        add_message_to_chat(gui_data, "Unrecognized command.\nCommands:\n  /create <username> <password>\n  /login <username> <password>\n  /logout\n  /quit or /exit\n");
    }
}

void log_error(GuiData *gui_data, const char *message)
{
    char error_message[BUF_SIZE];
    perror(message);
    snprintf(error_message, sizeof(error_message), "Error: %s: %s", message, strerror(errno));
    add_message_to_chat(gui_data, error_message);
}
