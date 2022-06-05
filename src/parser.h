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

struct http_request {
	int socket;
	enum method method;
	char host[512];
	char useragent[256];
	char xrealip[128];
	char xforwardedproto[128];
	char version[128];
	char uri[4096];
};

int http_parse(const char* request, int maxlen, struct http_request* req);

#endif
