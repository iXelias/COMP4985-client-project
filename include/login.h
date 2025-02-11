#ifndef LOGIN_H
#define LOGIN_H

void login_request(int sock, const char *username, const char *password);
void login_response(int sock);

#endif //LOGIN_H
