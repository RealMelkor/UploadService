/* See LICENSE for license details. */
#ifndef PARSER_H
#define PARSER_H

#include <netinet/in.h>
#include <stdio.h>
#include <time.h>

enum method {
	GET,
	HEAD,
	POST,
	PUT,
	DELETE,
	CONNECT,
	OPTIONS,
	TRACE
};

struct http_request {
	int socket;
	int data;
	struct sockaddr_in addr;
	enum method method;
	char host[512];
	char useragent[256];
	char xrealip[128];
	char xforwardedproto[128];
	char version[128];
	char uri[4096];
	char contentlength[32];
	char contenttype[512];
	char boundary[512];
	int boundary_found;
	size_t size;
	char* content;
	size_t content_allocated;
	char packet[32768];
	size_t length;
	size_t sent;
	int done;
	time_t started;
	time_t last;
	char header[1024];
	char updata[4096];
};

int http_parse(struct http_request* req);

#endif
