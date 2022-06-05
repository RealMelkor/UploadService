#ifndef SERVER_H
#define SERVER_H

#include "parser.h"

int load_file(char* path, char* uri);
//int serve(struct http_request* req);
int server_thread();
int server_init(int port);
int server_stop();

#endif
