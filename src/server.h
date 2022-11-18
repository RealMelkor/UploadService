/* See LICENSE for license details. */
#ifndef SERVER_H
#define SERVER_H

#include "parser.h"

int load_file(const char* path, const char* uri, const char* type);
int server_thread();
int server_init(int port);
int server_stop();

#endif
