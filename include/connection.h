#ifndef CONNECTION_H
#define CONNECTION_H
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

_Noreturn void usage(const char *prog_name, int exit_code, const char *message);
void           parse_args(int argc, char **argv, char **address, in_port_t *port);
in_port_t      parse_port(const char *prog_name, const char *port_str);
void           find_address(in_addr_t *address, char *address_str);
int            setup_client(struct sockaddr_in *addr, const char *addr_str, in_port_t port);
void           display_port(struct sockaddr_in *addr, const char host_address[INET_ADDRSTRLEN]);

#endif    // CONNECTION_H
