#include "server.h"
#include "parser.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
size_t
strlcpy(char *dst, const char *src, size_t dsize);
#endif

char header[] = 
"HTTP/1.0 200 OK\r\n"
"Connection: close\r\n"
"Content-Length: %d\r\n"
"Content-Type: %s\r\n"
"Server: uploadservice\r\n\r\n";
//"Date: Sun, 05 Jun 2022 14:20:40 GMT\r\n"
//"Last-Modified: Mon, 01 Jun 2022 09:55:40 GMT\r\n"

void print_now() {
	time_t now = time(NULL);
	struct tm tm = *localtime(&now);
	printf("[%d/%02d/%02d %02d:%02d:%02d] ", 
		tm.tm_year+1900, tm.tm_mon, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec);
}

uint32_t fnv(char* ptr, int len) {
	uint32_t hash = 2166136261;
	char* start = ptr;
	while (ptr - start < len) {
		hash = hash * 2166136261;
		hash = hash ^ *ptr;
		ptr++;
	}
	return hash;
}

int verify_name = 0;

struct file {
	char* data;
	size_t size;
	size_t length;
	char* uri;
	char type[256];
	int hash;
};

struct file* files = NULL;
int files_count;

int load_file(char* path, char* uri, char* type) {
	FILE* f = fopen(path, "rb");
	if (!f) {
		printf("%s: failed to open file\n", path);
		return -1;
	}
	fseek(f, 0, SEEK_END);
	size_t len = ftell(f);
	fseek(f, 0, SEEK_SET);
	char buf[4096];
	size_t header_len = snprintf(buf, sizeof(buf), header, len, type);
	if (header_len >= sizeof(buf)) {
		printf("%s: header buffer overflow\n", path);
		return -1;
	}
	files = realloc(files, (files_count + 1) * sizeof(struct file));
	struct file* file = &files[files_count];
	file->data = malloc(header_len + len);
	strlcpy(file->data, buf, header_len+1);
	file->size = header_len + len;
	if (fread(&file->data[header_len], 1, len, f) != len) {
		free(file->data);
		fclose(f);
		printf("%s: failed to read file content\n", path);
		return -1;
	}
	file->uri = malloc(strlen(uri));
	strcpy(file->uri, uri);
	strlcpy(file->type, type, sizeof(file->type));
	file->length = len;
	file->hash = fnv(file->uri, strnlen(file->uri, strlen(uri)));
	for (int i = 0; !verify_name && i < files_count - 1; i++) {
		if (files[i].hash == files[files_count].hash) {
			verify_name = 1;
			break;
		}
	}
	files_count++;
	fclose(f);
	return 0;
}

#include <sys/socket.h>
#include <netinet/in.h>

char data_404[] = 
"<html>\n"
"<head>\n"
"        <title>404 Not Found</title>\n"
"</head>\n"
"<body>\n"
"        <h1>404 Not Found</h1>\n"
"</body>\n"
"</html>\n";

int server_serve(struct http_request* req) {
	int hash = fnv(req->uri, strnlen(req->uri, sizeof(req->uri)));
	struct file* file = NULL;
	for (int i = 0; i < files_count; i++) {
		if (hash == files[i].hash) file = &files[i];
	}
	if (file == NULL) {
		char packet[4096];
		bzero(packet, sizeof(packet));
		size_t l = snprintf(packet, sizeof(packet),
				header, sizeof(data_404) - 1, "text/html");
		if (l >= sizeof(packet)) {
			printf("packet buffer overflowing");
			return -1;
		}
		l += strlcpy(&packet[l], data_404, sizeof(packet) - l);
		send(req->socket, packet, l+1, 0);
		return 404;
	}
	size_t bytes = 0;
	while (bytes < file->size) {
		int ret = send(req->socket, &file->data[bytes], file->size - bytes, 0);
		if (ret <= 0) break;
		bytes += ret;
	}
	return 200;
}

int listener;
int server_init(int port) {
	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener == -1) {
		printf("Failed to create socket\n");
		return -1;
	}
#ifdef DEBUG
	// instant reset, useful for testing
	struct linger sl;
        sl.l_onoff = 1;
        sl.l_linger = 0;
        setsockopt(listener, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
#endif
	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(port);
	if (bind(listener, (struct sockaddr*)&addr, sizeof(addr))) {
                printf("Failed to bind socket on port %d\n", port);
		return -1;
        }
	if (listen(listener, 5)) {
                printf("Failed to listen on port %d\n", port);
		return -1;
	}
	print_now();
	printf("Listening on port %d\n", port);
	return 0;
}

int server_accept(struct http_request* req) {
	bzero(req, sizeof(struct http_request));
	unsigned int len = sizeof(req->addr);
	int socket = accept(listener, (struct sockaddr*)&req->addr, &len);
	if (socket == -1) {
		printf("Failed to accept socket\n");
		return -1;
	}
	req->socket = socket;
	return 0;
}

int server_recv(struct http_request* req) {
	char packet[4096];
	int bytes = recv(req->socket, packet, sizeof(packet), 0);
	if (bytes <= 0) return -1;
	if (http_parse(packet, bytes, req)) {
		printf("Invalid request\n");
		return -1;
	}
	return 0;
}

int server_thread() {
	while (1) {
		struct http_request req;
		if (server_accept(&req)) continue;
		if (server_recv(&req)) {
			close(req.socket);
			continue;
		}

		print_now();
		int ret = server_serve(&req);
#ifdef NO_PROXY
		uint8_t* ptr = (uint8_t*)&req.addr.sin_addr.s_addr;
		printf("%d.%d.%d.%d, %s, requested %s [%d]\n",
		       ptr[0], ptr[1], ptr[2], ptr[3], req.useragent, req.uri, ret);
#else
		printf("%s, %s, requested %s [%d]\n",
		       req.xrealip, req.useragent, req.uri, ret);
#endif
		close(req.socket);
	}
	return 0;
}

int server_stop() {
	close(listener);
	return 0;
}
