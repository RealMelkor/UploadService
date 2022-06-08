#define _GNU_SOURCE
#include "server.h"
#include "parser.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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

#include <sys/stat.h>
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

char data_upload[] = 
"<html>\n"
"<head>\n"
"        <title>File uploaded</title>\n"
"</head>\n"
"<body>\n"
"        <h1>File succesfully uploaded</h1>\n"
"        <p>Download link : <a href=\"%s\">%s</a></p>\n"
"</body>\n"
"</html>\n";

int server_upload(struct http_request* req) {
	if (!req->content) return -1;
		int boundary_len = strnlen(req->boundary, sizeof(req->boundary));
	char* end = memmem(&req->content[req->size - boundary_len*2], boundary_len * 2, 
			   req->boundary, boundary_len);
	if (!end) return -1;
	end -= 4;

	// path + name
	char* start = strstr(req->content, "\r\n\r\n");
	if (!start) start = req->content;
	char file_name[256];
	char* name_ptr = strstr(start, "filename=\"");
	int name_fail = 1;
	if (name_ptr) {
		name_ptr += sizeof("filename=\"") - 1;
		char* name_end = strstr(name_ptr, "\"\r\n");
		if (name_end && (size_t)(name_end - name_ptr) < sizeof(file_name)) {
			strlcpy(file_name, name_ptr, name_end - name_ptr + 1);
			name_fail = 0;
		}
	}
	if (name_fail) {
		strlcpy(file_name, "generic.dat", sizeof(file_name));
	}
	time_t now = time(NULL);
	int hash = fnv(start, end - start) + fnv((char*)&now, sizeof(now));
	int hash2 = fnv(req->boundary, boundary_len) - fnv((char*)&now, sizeof(now));
	char path[1024];
	snprintf(path, sizeof(path), "/download/%x%x/%s", hash, hash2, file_name);
	char file_path[1024];
	//

	start = strstr(start+4, "\r\n\r\n");
	if (!start) start = req->content;
	start += 4;
	char* slash_ptr = strrchr(path, '/');
	if (!slash_ptr) return -1;
	*slash_ptr = '\0';
	mkdir(&path[1], 0700);
	*slash_ptr = '/';
	FILE* f = fopen((char*)&path[1], "wb");
	printf("%s\n", &file_path[1]);
	if (!f)
		return -1;
	if (fwrite(start, 1, end - start, f) != (size_t)(end - start))
		return -1;
	fclose(f);
	//
	char data[2048];
	int len = snprintf(data, sizeof(data), data_upload, path, file_name);
	char up_header[1024];
	snprintf(up_header, sizeof(up_header), header, len, "text/html");
	char packet[4096];
	size_t size = snprintf(packet, sizeof(packet), "%s%s", up_header, data);
	size_t bytes = 0;
	while (bytes < size) {
		int ret = send(req->socket, &packet[bytes], size - bytes, 0);
		if (ret <= 0) break;
		bytes += ret;
	}
	return 200;
}

int server_download(struct http_request* req) {
	char* ptr = strstr(req->uri, "/download/");
	if (!ptr) {
		return -1;
	}
	ptr += sizeof("/download/") - 1;
	char* file_name = strchr(ptr, '/');
	if (!file_name)
		return -1;
	*file_name = '\0';
	char* error = NULL;
	long long hash = strtoull(ptr, &error, 16);
	printf("%llx, %s, %d\n", hash, ptr, *error);
	if (!hash || (error && *error))
		return -1;
	*file_name = '/';
	printf("%s | %s, %llx\n", ptr, file_name, hash);
	if ((file_name[1] == '.' &&
	    file_name[2] == '.') ||
	    strchr(file_name+1, '/')
	   )
		return -1;
	file_name++;
	ptr -= sizeof("/download/") - 2;
	printf("open : %s\n", ptr);
	FILE* f = fopen(ptr, "rb");
	if (!f) return -1;
	fseek(f, 0, SEEK_END);
	size_t length = ftell(f);
	fseek(f, 0, SEEK_SET);
	char* data = malloc(length);
	if (fread(data, 1, length, f) != length) {
		free(data);
		fclose(f);
		return -1;
	}
	size_t bytes = 0;
	while (bytes < length) {
		int ret = send(req->socket, &data[bytes], length - bytes, 0);
		if (ret <= 0) break;
		bytes += ret;
	}
	fclose(f);
	free(data);
	return 0;
}

int server_serve(struct http_request* req) {
	if (req->method == POST && !strncmp(req->uri, "/upload", sizeof(req->uri))) {
		if (!server_upload(req)) return 0;
		else goto err_404;
	}
	if (req->method == GET && !strncmp(req->uri, "/download/", sizeof("/download/") - 1)) {
		if (!server_download(req)) return 0;
		else goto err_404;
	}
	if (req->method != GET) goto err_404;
	int hash = fnv(req->uri, strnlen(req->uri, sizeof(req->uri)));
	struct file* file = NULL;
	for (int i = 0; i < files_count; i++) {
		if (hash == files[i].hash) file = &files[i];
	}
	if (file == NULL) {
err_404:;
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
	if (req->size < sizeof(req->packet) - sizeof(req->packet)/4) {
		req->content = (char*)req->packet;
	} else if (req->size + sizeof(req->packet)*2 >= req->content_allocated){
		int copy = 0;
		if (req->content == req->packet) {
			req->content = NULL;
			copy = 1;
		}
		req->content = realloc(req->content,
				req->content_allocated + sizeof(req->packet) * 2);
		if (copy)
			strlcpy(req->content, req->packet, req->size);
		req->content_allocated += sizeof(req->packet) * 2;
	}
	int bytes = recv(req->socket,
			(req->content == req->packet)?
			(&req->content[req->size]):
			req->packet,
			(req->content == req->packet)?
			(sizeof(req->packet) - req->size):
			sizeof(req->packet),
			0);
	if (req->content != req->packet) {
		memcpy(&req->content[req->size], req->packet, bytes);
	}
	if (bytes <= 0) return -1;
	if (!req->boundary_found) {
		char* ptr = strstr(&req->content[req->size], "boundary=");
		if (ptr) {
			ptr += sizeof("boundary=");
			char* start = ptr;	
			while (ptr++ && *ptr != '\r');
			strlcpy(req->boundary, start, ptr - start);
			req->boundary_found = 1;
		}
	}
	req->size += bytes;
	while (req->boundary_found) {
		char* ptr = strstr(req->content, req->boundary);
		if (!ptr) break;
		ptr = strstr(ptr+1, req->boundary);
		if (!ptr) break;
		int blen = strnlen(req->boundary, sizeof(req->boundary));
		void* end = memmem(&req->content[req->size - blen * 2 + 1], bytes, req->boundary, blen);
		if (!end || end <= (void*)ptr) break;
		return 0;
	}
	if (!req->boundary_found &&
	    req->content[req->size-1] == '\n' &&
	    req->content[req->size-2] == '\r' &&
	    req->content[req->size-3] == '\n' &&
	    req->content[req->size-4] == '\r') {
		return 0;
	}
	return 1;
}

#include <poll.h>
struct http_request requests[1024];
struct pollfd fds[1024];
int requests_count = 0;

int new_request() {
	bzero(&requests[requests_count], sizeof(struct http_request));
	if (server_accept(&requests[requests_count])) {
		return -1;
	}
	fds[requests_count+1].fd = requests[requests_count].socket;
	fds[requests_count+1].events = POLLIN;
	requests_count++;
	return 0;
}

void print_req(struct http_request* req, int code) {
#ifdef NO_PROXY
	uint8_t* ptr = (uint8_t*)&req->addr.sin_addr.s_addr;
	printf("%d.%d.%d.%d, %s, requested %s [%d]\n",
	       ptr[0], ptr[1], ptr[2], ptr[3], req->useragent, req->uri, code);
#else
	printf("%s, %s, requested %s [%d]\n",
	       req->xrealip, req->useragent, req->uri, code);
#endif

}

int server_thread() {
	fds[0].fd = listener;
	fds[0].events = POLLIN;
	while (1) {
		int nfds = requests_count + 1;
		int ready = poll(fds, nfds, -1);
		if (ready == -1) break;
		if (fds[0].revents == POLLIN) {
			if (new_request()) printf("Failed to accept client\n");
		}
		for (int i = 0; i < requests_count; i++) {
			if (fds[i+1].revents == POLLIN) {
				int ret = server_recv(&requests[i]);
				if (ret == 1) continue;
				if (ret == 0) {
					http_parse(&requests[i]);
					server_serve(&requests[i]);
				}
				if (requests[i].packet != requests[i].content)
					free(requests[i].content);

				close(requests[i].socket);
				bzero(&fds[i+1], sizeof(struct pollfd));
			}
		}
	}
	return 0;
}

int server_stop() {
	close(listener);
	return 0;
}
