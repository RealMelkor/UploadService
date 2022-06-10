#ifndef PARSER_H
#define PARSER_H

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

#include <netinet/in.h>
#include <stdio.h>
struct http_request {
	int socket;
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
	char packet[4096];
	//char* data;
	size_t length;
	size_t sent;
	FILE* data;
};

int http_parse(struct http_request* req);

#endif
