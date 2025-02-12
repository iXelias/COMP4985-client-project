#ifndef LOGIN_H
#define LOGIN_H

void account_request(int sock, const char *username, const char *password, int request_type);
void account_logout(int sock);
void account_response(int sock);

#endif    // LOGIN_H
