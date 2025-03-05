#include "../include/connection.h"
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PREFIX "192.168"
#define BASE_TEN 10

_Noreturn void usage(const char *prog_name, int exit_code, const char *message)
{
    if(message)
    {
        fprintf(stderr, "%s\n", message);
    }

    fprintf(stderr, "Usage: %s [-h] [-i <address>] [-p <port>]\n", prog_name);
    fputs("-h Display this help message\n", stderr);
    fputs("-i <address>\n", stderr);
    fputs("-p <port>\n", stderr);
    exit(exit_code);
}

void parse_args(int argc, char **argv, char **address, in_port_t *port)
{
    int opt;
    *address = NULL;
    *port    = 0;

    while((opt = getopt(argc, argv, "hi:p:")) != -1)
    {
        switch(opt)
        {
            case 'h':
                usage(argv[0], EXIT_SUCCESS, NULL);
            case 'i':
                *address = optarg;
                break;
            case 'p':
                *port = parse_port(argv[0], optarg);
                break;
            case '?':
                usage(argv[0], EXIT_FAILURE, "Error: Unknown option");
            default:
                usage(argv[0], EXIT_FAILURE, NULL);
        }
    }
}

in_port_t parse_port(const char *prog_name, const char *port_str)
{
    char     *endptr;
    uintmax_t parsed_val;
    errno      = 0;
    parsed_val = strtoumax(port_str, &endptr, BASE_TEN);

    if(errno != 0)
    {
        perror("Error parsing the port.");
        exit(EXIT_FAILURE);
    }
    if(*endptr != '\0')
    {
        usage(prog_name, EXIT_FAILURE, "Invalid characters in port.");
    }
    if(parsed_val > UINT16_MAX)
    {
        usage(prog_name, EXIT_FAILURE, "Entered port is out of range.");
    }
    return (in_port_t)parsed_val;
}

void find_address(in_addr_t *address, char *address_str)
{
    struct ifaddrs       *ifaddr;
    const struct ifaddrs *ifa;

    if(getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if(ifa->ifa_addr == NULL)
        {
            continue;
        }
        if(ifa->ifa_addr->sa_family == AF_INET)
        {
            if(getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), address_str, INET_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST) != 0)
            {
                perror("getnameinfo");
                continue;
            }
            if(strncmp(address_str, PREFIX, strlen(PREFIX)) == 0)
            {
                inet_pton(AF_INET, address_str, address);
                break;
            }
        }
    }
    if(ifa == NULL)
    {
        freeifaddrs(ifaddr);
        perror("No Address");
        exit(EXIT_FAILURE);
    }
    freeifaddrs(ifaddr);
}

int setup_client(struct sockaddr_in *addr, const char *addr_str, in_port_t port)
{
    int       fd;
    socklen_t addr_len = sizeof(struct sockaddr);

    // Ensure addr_str is not NULL
    if(addr_str == NULL)
    {
        fprintf(stderr, "Error: addr_str is NULL\n");
        exit(EXIT_FAILURE);
    }

    // Convert the IP address to binary form
    if(inet_pton(AF_INET, addr_str, &addr->sin_addr) <= 0)
    {
        if(inet_pton(AF_INET, addr_str, &addr->sin_addr) == 0)
        {
            fprintf(stderr, "Error: Invalid address format for %s\n", addr_str);
        }
        else
        {
            perror("inet_pton failed");
        }
        exit(EXIT_FAILURE);
    }

    addr->sin_family = AF_INET;
    addr->sin_port   = htons(port);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0)
    {
        perror("Failed to create socket");
        exit(EXIT_FAILURE);
    }

    if(connect(fd, (struct sockaddr *)addr, addr_len) < 0)
    {
        perror("connect");
        goto cleanError;
    }

    printf("Connected to %s:%d\n", addr_str, port);
    return fd;

cleanError:
    if(fd != 0)
    {
        close(fd);
    }
    exit(EXIT_FAILURE);
}

// cppcheck-suppress constParameterPointer
void display_port(struct sockaddr_in *addr, const char host_address[INET_ADDRSTRLEN])
{
    char port_str[NI_MAXSERV];
    if(getnameinfo((struct sockaddr *)addr, sizeof(struct sockaddr_in), NULL, 0, port_str, sizeof(port_str), NI_NUMERICSERV) != 0)
    {
        perror("getnameinfo");
        exit(EXIT_FAILURE);
    }
    printf("Listening on %s:%s\n", host_address, port_str);
}
