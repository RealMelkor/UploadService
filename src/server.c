#include "server.h"
#include "parser.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
	size_t length;
	char* uri;
	int hash;
};

struct file* files = NULL;
int files_count;

int load_file(char* path, char* uri) {
	FILE* f = fopen(path, "rb");
	if (!f) return -1;
	fseek(f, 0, SEEK_END);
	size_t len = ftell(f);
	fseek(f, 0, SEEK_SET);
	files = realloc(files, (files_count + 1) * sizeof(struct file));
	struct file* file = &files[files_count];
	file->data = malloc(len);
	if (fread(file->data, 1, len, f) != len) {
		free(file->data);
		fclose(f);
		return -1;
	}
	file->uri = malloc(strlen(uri));
	strcpy(file->uri, uri);
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
		send(req->socket, data_404, sizeof(data_404), 0);
		return 404;
	}
	size_t bytes = 0;
	while (bytes < file->length) {
		int ret = send(req->socket, file->data, file->length, 0);
		if (ret <= 0) break;
		bytes += ret;
		printf("%ld/%ld, %d\n", bytes, file->length, ret);
	}
	return 0;
}

int listener;
int server_init(int port) {
	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener == -1) {
		printf("Failed to create socket\n");
		return -1;
	}
	// instant reset
	struct linger sl;
        sl.l_onoff = 1;
        sl.l_linger = 0;
        setsockopt(listener, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
	//
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
	struct sockaddr_in addr;
	unsigned int len;
	int socket = accept(listener, (struct sockaddr*)&addr, &len);
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
		printf("%s, %s, requested %s\n", req.xrealip, req.useragent, req.uri);
		server_serve(&req);
		close(req.socket);
	}
	return 0;
}

int server_stop() {
	close(listener);
	return 0;
}
