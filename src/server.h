#ifndef SERVER_H
#define SERVER_H

#include "parser.h"

int load_file(char* path, char* uri, char* type);
int server_thread();
int server_init(int port);
int server_stop();

#endif
