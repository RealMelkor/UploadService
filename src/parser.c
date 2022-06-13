#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#ifdef __linux__
// OpenBSD implementation of strlcpy
// https://github.com/libressl-portable/openbsd/blob/master/src/lib/libc/string/strlcpy.c
size_t
strlcpy(char *dst, const char *src, size_t dsize)
{
	const char *osrc = src;
	size_t nleft = dsize;

	/* Copy as many bytes as will fit. */
	if (nleft != 0) {
		while (--nleft != 0) {
			if ((*dst++ = *src++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src. */
	if (nleft == 0) {
		if (dsize != 0)
			*dst = '\0';		/* NUL-terminate dst */
		while (*src++)
			;
	}

	return(src - osrc - 1);	/* count does not include NUL */
}
#endif

const char* methods[] = {
	"GET",
	"HEAD",
	"POST",
	"PUT",
	"DELETE",
	"CONNECT",
	"OPTIONS",
	"TRACE"
};

int parse_method(const char* method, size_t len) {
	for (size_t i = 0; i < sizeof(methods)/sizeof(const char*); i++)
		if (!strncmp(method, methods[i], len)) return i;
	return -1;
}

int get_parameter(struct http_request* req, char* name, int len, char** ptr, int* psizeof) {
	if (!strncmp(name, "Host", len)) {
		*ptr = req->host;
		*psizeof = sizeof(req->host);
		return 0;
	}
	if (!strncmp(name, "X-Real-IP", len)) {
		*ptr = req->xrealip;
		*psizeof = sizeof(req->xrealip);
		return 0;
	}
	if (!strncmp(name, "X-Forwarded-Proto", len)) {
		*ptr = req->xforwardedproto;
		*psizeof = sizeof(req->xforwardedproto);
		return 0;
	}
	if (!strncmp(name, "User-Agent", len)) {
		*ptr = req->useragent;
		*psizeof = sizeof(req->useragent);
		return 0;
	}
	if (!strncmp(name, "Content-Type", len)) {
		*ptr = req->contenttype;
		*psizeof = sizeof(req->contenttype);
		return 0;
	}
	if (!strncmp(name, "Content-Length", len)) {
		*ptr = req->contentlength;
		*psizeof = sizeof(req->contentlength);
		return 0;
	}
	return -1;
}

int http_parse(struct http_request* req) {
	const char* end = req->packet + req->size;
	const char* ptr = req->packet;
	int i = 0;
	const char* pos[3];
	// header
	while (++ptr && ptr < end - 1) {
		if (*ptr == '\r' && *(ptr+1) == '\n') {
			pos[i] = ptr;
			if (i != 2) return -1;
			break;
		}
		if (*ptr != ' ') continue;
		if (i > 1) {
			return -1;
		}
		pos[i] = ptr+1;
		i++;
	}
	char buf[64];
	size_t len = pos[0] - req->packet;
	if (len >= sizeof(buf)) return -2;
	strlcpy(buf, req->packet, len);
	req->method = parse_method(buf, len);
	len = pos[1] - pos[0];
	if (len >= sizeof(req->uri)) return -2;
	strlcpy(req->uri, pos[0], len);
	len = ptr - pos[1] + 1;
	if (len >= sizeof(req->version)) return -2;
	strlcpy(req->version, pos[1], len);

	// parameters
	int in_value = 0;
	char parameter[4096];
	char* value = NULL;
	int sizeof_value = 0;
	ptr+=2;
	const char* start = ptr;
	ptr--;
	req->boundary_found = 0;
	while (ptr++ && ptr < end - 1) {
		if ((ptr-1)[0] == '\n' && req->boundary_found &&
		    !memcmp(ptr, req->boundary, strnlen(req->boundary, sizeof(req->boundary)))) {
			start = ptr;
			break;
		}
		if (in_value && ptr + sizeof("boundary=") < end - 1 &&
		    !memcmp(ptr, "boundary=", sizeof("boundary=")-1)) {
			const char* bstart = ptr + sizeof("boundary=") - 1;
			ptr += sizeof("boundary=") - 2;
			while (ptr++ && ptr < end - 1 && *ptr != '\n' && *ptr != '\r')
				req->boundary[ptr - bstart] = *ptr;
			req->boundary_found = 1;
		}
		if (*ptr == '\r' && *(ptr+1) == '\n') {
			ptr+=2;
			start = ptr;
			in_value = 0;
		}
		if (!in_value && *ptr == ':') {
			if ((size_t)(ptr - start) > sizeof(parameter)) {
				return -1;
			}
			strlcpy(parameter, start, ptr - start + 1);
			if (!get_parameter(req, parameter, sizeof(parameter),
					   &value, &sizeof_value)) {
				while (++ptr && ptr < end - 1 && *ptr != ' ') ;
				start = ptr+1;
				in_value = 1;
				continue;
			}
			while (++ptr && ptr < end - 1 && *ptr != '\n') ;
			++ptr;
			start = ptr;
		}
		if (in_value) {
			if (ptr - start > sizeof_value) {
				return -1;
			}
			value[ptr - start] = *ptr;
		}
	}
	return 0;
}
