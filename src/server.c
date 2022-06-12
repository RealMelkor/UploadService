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
"        <a href=\"/\">Go back</a>\n"
"        <h1>404 Not Found</h1>\n"
"</body>\n"
"</html>\n";

char data_upload[] = 
"<html>\n"
"<head>\n"
"        <title>File uploaded</title>\n"
"</head>\n"
"<body>\n"
"        <a href=\"/upload\">Go back</a>\n"
"        <h1>File succesfully uploaded</h1>\n"
"        <p>Download link : <a href=\"%s\">%s</a></p>\n"
"</body>\n"
"</html>\n";

int path_to_url(const char* path, char* url, int len) {
	int j = 0;
	for (int i = 0; path[i] && j < len; i++) {
		char c = path[i];
		if ((c >= 'a' && c <= 'z') ||
		    (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') ||
		    c == '.' || c == '/') {
			url[j] = path[i];
			j++;
			continue;
		}
		snprintf(&url[j], len - j, "%%%02X", c);
		j += 3;
	}
	url[j] = '\0';
	return j;
}

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
	if (!f)
		return -1;
	if (fwrite(start, 1, end - start, f) != (size_t)(end - start))
		return -1;
	fclose(f);
	//
	char data[4096];
	char url[2048];
	path_to_url(path, url, sizeof(url));
	int len = snprintf(data, sizeof(data), data_upload, url, file_name);
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
	return 0;
}

const char* extension[] = {
	".html",
	".htm",
	".txt",
	".webm",
	".mp4",
	".gif",
	".png",
	".jpg",
	".jpeg",
	".bmp",
	".ico",
	".svg",
	".pdf",
	".tar",
	".zip",
	".json"
};

const char* mime[] = {
	"text/html",
	"text/html",
	"text/plain",
	"video/webm",
	"video/mp4",
	"image/gif",
	"image/png",
	"image/jpeg",
	"image/jpeg",
	"image/bmp",
	"image/vnd.microsoft.icon",
	"image/svg+xml",
	"application/pdf",
	"application/tar",
	"application/zip",
	"application/json"
};

int mime_from_extension(const char* ext) {
	for (size_t i = 0; i < sizeof(mime)/sizeof(char*); i++)
		if (!strcmp(ext, extension[i])) return i;
	return -1;
}

int is_hex(char c) {
	return ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || (c >= '0' && c <= '9'));
}

int format_path(const char* data, char* buf, int len) {
	int j = 0;
	for (int i = 0; data[i] && j < len; i++) {
		while (data[i] == '%') {
			char hex[3];
			hex[0] = data[i+1];
			if (!is_hex(hex[0])) break;
			hex[1] = data[i+2];
			if (!is_hex(hex[1])) break;
			hex[2] = '\0';
			char* error = NULL;
			unsigned int value = strtoul(hex, NULL, 16);
			if (!value || (error && *error) || value == '.')
				break;
			i+=2;
			buf[j] =  value;
			j++;
			goto end;
		}
		buf[j] = data[i];
		j++;
end:;
	}
	buf[j] = 0;
	return 0;
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
	if (!hash || (error && *error))
		return -1;
	*file_name = '/';
	if ((file_name[1] == '.' &&
	    file_name[2] == '.') ||
	    strchr(file_name+1, '/')
	   )
		return -1;
	file_name++;
	ptr -= sizeof("/download/") - 2;
	char path[1024];
	format_path(ptr, path, sizeof(path));
	FILE* f = fopen(path, "rb");
	if (!f) return -1;
	fseek(f, 0, SEEK_END);
	size_t length = ftell(f);
	fseek(f, 0, SEEK_SET);
	req->length = length;
	req->data = f;
	char header_buf[1024];
	// mime
	char* ext = strrchr(file_name, '.');
	int mime_id = !ext?-1:mime_from_extension(ext);
	const char* mime_ptr = ((mime_id==-1)?"application/octet-stream":mime[mime_id]);
	// header
	int header_len = snprintf(header_buf, sizeof(header_buf),
				   header, length, mime_ptr);
	send(req->socket, header_buf, header_len, 0);
	return 0;
}

int server_send(struct http_request* req) {
	char data[32768];
	size_t to_send = req->length - req->sent;
	if (to_send > 32768) to_send = 32768;
	if (fread(data, 1, to_send, req->data) != to_send) return -1;
	size_t ret = send(req->socket, data, to_send, 0);
	if (ret <= 0) return -1;
	req->sent += ret;
	if (ret != to_send)
		fseek(req->data, req->sent, SEEK_SET);
	if (req->sent >= req->length) return 0;
	return 1;
}

int server_serve(struct http_request* req) {
	if (req->method == POST && !strncmp(req->uri, "/upload", sizeof(req->uri))) {
		if (!server_upload(req)) return 200;
		else goto err_404;
	}
	if (req->method == GET && !strncmp(req->uri, "/download/", sizeof("/download/") - 1)) {
		if (!server_download(req)) return 200;
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
			memcpy(req->content, req->packet, req->size);
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
	if (bytes <= 0) return -1;
	if (req->content != req->packet) {
		memcpy(&req->content[req->size], req->packet, bytes);
	}
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
#define MAX_REQUESTS 4096
#define TIMEOUT_SINCE_STARTED 1200000
#define TIMEOUT_SINCE_LAST 10000
struct http_request requests[MAX_REQUESTS];
struct pollfd fds[MAX_REQUESTS];
size_t requests_count = 0;

int new_request() {
	int new = 1;
	size_t i = 0;
	time_t now = time(NULL);
	for (; i < requests_count; i++)
		if (requests[i].done ||
		    now - requests[i].started >= TIMEOUT_SINCE_STARTED ||
		    now - requests[i].last >= TIMEOUT_SINCE_LAST) {
			new = 0;
			break;
		}
	if (new && i >= sizeof(requests)/sizeof(struct http_request) - 1) {
		return -1;
	}
	bzero(&requests[i], sizeof(struct http_request));
	if (server_accept(&requests[i])) {
		return -1;
	}
	fds[i+1].fd = requests[i].socket;
	fds[i+1].events = POLLIN;
	requests[i].last = requests[i].started = time(NULL);
	if (new)
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
	bzero(requests, sizeof(requests));
	for (size_t i = 1; i < sizeof(fds)/sizeof(struct pollfd); i++) {
		fds[i].fd = -1;
		fds[i].events = POLLIN;
	}
	fds[0].fd = listener;
	fds[0].events = POLLIN;
	while (1) {
		int nfds = requests_count + 1;
		int ready = poll(fds, nfds, -1);
		if (ready == -1) break;
		if (fds[0].revents == POLLIN) {
			if (new_request())
				printf("Failed to accept client\n");
		}
		int ret = 0;
		for (size_t i = 0; i < requests_count; i++) {
			struct http_request* req = &requests[i];
			switch (fds[i+1].revents) {
			case 0:
				break;
			case POLLOUT:
				requests[i].last = time(NULL);
				if (req->length <= req->sent)
					goto clean;
send_data:;
				ret = server_send(req);
				if (ret == 1 || ret == 0) continue;
				break;
			case POLLIN:
				requests[i].last = time(NULL);
				ret = server_recv(req);
				if (ret == 1) continue;
				if (ret == 0) {
					http_parse(req);
					print_req(req, server_serve(req));
					if (req->data) {
						fds[i+1].events = POLLOUT;
						goto send_data;
					}
				}
clean:
				if (req->packet != req->content)
					free(req->content);
				if (req->data)
					fclose(req->data);

				close(req->socket);
				req->done = 1;
				if (i + 1 == requests_count)
					requests_count--;
				bzero(&fds[i+1], sizeof(struct pollfd));
				fds[i+1].fd = -1;
				fds[i+1].events = POLLIN;
				break;
			default:
				fds[i+1].fd = -1;
				fds[i+1].events = POLLIN;
			}
		}
	}
	return 0;
}

int server_stop() {
	close(listener);
	return 0;
}
