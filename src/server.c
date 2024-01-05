/* See LICENSE for license details. */
#if defined(__linux__) || defined(__sun)
#define HAS_SENDFILE
#include <sys/sendfile.h>
#endif
#ifdef __FreeBSD__
#define HAS_SENDFILE
#define __BSD_VISIBLE 1
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#endif
#include "server.h"
#include "parser.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#ifdef __sun
#include <signal.h>
#endif
#define _GNU_SOURCE
size_t strlcpy(char*, const char*, size_t);

char header[] = 
"HTTP/1.0 200 OK\r\n"
"Connection: close\r\n"
"Content-Length: %d\r\n"
"Content-Type: %s\r\n"
"Server: uploadservice\r\n\r\n";

void
print_now()
{
	time_t now = time(NULL);
	struct tm tm = *localtime(&now);
	printf("[%d/%02d/%02d %02d:%02d:%02d] ", 
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec);
}

uint32_t
fnv(const char* ptr, int len)
{
	uint32_t hash = 2166136261;
	const char* start = ptr;
	while (ptr - start < len) {
		hash = hash * 2166136261;
		hash = hash ^ *ptr;
		ptr++;
	}
	return hash;
}

int verify_name = 0, listener = 0;

struct file {
	char* data;
	size_t size;
	size_t length;
	char* uri;
	char type[256];
	int hash;
};

#define FILES_TABLE_SIZE 64
struct file files[FILES_TABLE_SIZE] = {0};

int
load_file(const char* path, const char* uri, const char* type)
{
	char buf[4096];
	int hash, i;
	size_t len, header_len;
	FILE *f;

	f = fopen(path, "rb");
	if (!f) {
		printf("%s: failed to open file\n", path);
		return -1;
	}
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	fseek(f, 0, SEEK_SET);
	header_len = snprintf(buf, sizeof(buf), header, len, type);
	if (header_len >= sizeof(buf)) {
		printf("%s: header buffer overflow\n", path);
		return -1;
	}
	hash = fnv(uri, strlen(uri))%FILES_TABLE_SIZE;
	files[hash].data = malloc(header_len + len);
	strlcpy(files[hash].data, buf, header_len+1);
	files[hash].size = header_len + len;
	if (fread(&files[hash].data[header_len], 1, len, f) != len) {
		free(files[hash].data);
		fclose(f);
		printf("%s: failed to read file content\n", path);
		return -1;
	}
	files[hash].uri = malloc(strlen(uri));
	strcpy(files[hash].uri, uri);
	strlcpy(files[hash].type, type, sizeof(files[hash].type));
	files[hash].length = len;
	i = 0;
	for (; i < FILES_TABLE_SIZE; i++) {
		if (files[i].hash != hash) continue;
		printf("Files hash table is too small, "
		       "a collision happened\n");
		exit(0);
	}
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

int
path_to_url(const char* path, char* url, int len)
{
	int j = 0;
	int i = 0;
	for (; path[i] && j < len; i++) {
		char c = path[i];
		if ((c >= 'a' && c <= 'z') ||
		    (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') ||
		    c == '.' || c == '/' || c == '_') {
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

int
server_upload(struct http_request* req)
{
	char file_name[256], path[1024], url[2048];
	char *start, *name_ptr, *slash_ptr;
	int name_fail, fd, len;

	/* path + name */
	start = strstr(req->packet, "\r\n\r\n");
	if (!start) start = req->packet;
	name_ptr = strstr(start, "filename=\"");
	name_fail = 1;
	if (name_ptr) {
		char* name_end;

		name_ptr += sizeof("filename=\"") - 1;
		name_end = strstr(name_ptr, "\"\r\n");
		if (name_end && (size_t)(name_end - name_ptr) <
		    sizeof(file_name)) {
			strlcpy(file_name, name_ptr, name_end - name_ptr + 1);
			name_fail = 0;
		}
	}
	if (name_fail)
		strlcpy(file_name, "generic.dat", sizeof(file_name));
	snprintf(path, sizeof(path), "/download/%08X%08X/%s",
		 (unsigned)(rand() * rand() + rand()),
		 (unsigned)(rand() * rand() - rand()), file_name);

	start = strstr(start+4, "\r\n\r\n");
	if (!start) start = req->content;
	slash_ptr = strrchr(path, '/');
	if (!slash_ptr) return -1;
	*slash_ptr = '\0';
	mkdir(&path[1], 0700);
	*slash_ptr = '/';
	fd = open((char*)&path[1], O_WRONLY | O_CREAT, 0600);
	if (fd < 0)
		return -1;
	req->data = fd;
	path_to_url(path, url, sizeof(url));
	len = snprintf(req->updata, sizeof(req->updata),
		       data_upload, url, file_name);
	snprintf(req->header, sizeof(req->header), header, len, "text/html");
	http_parse(req);
	return 0;
}

const char* extension[] = {
	".html",
	".htm",
	".txt",
	".aac",
	".mp3",
	".flac",
	".ogg",
	".wav",
	".midi",
	".avi",
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
	"audio/mpeg",
	"audio/mpeg",
	"audio/flac",
	"audio/ogg",
	"audio/wav",
	"audio/midi",
	"video/x-msvideo",
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

int
mime_from_extension(const char* ext)
{
	size_t i;
	for (i = 0; i < sizeof(mime)/sizeof(char*); i++)
		if (!strcasecmp(ext, extension[i])) return i;
	return -1;
}

int
is_hex(char c)
{
	return ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') ||
		(c >= '0' && c <= '9'));
}

int
format_path(const char* data, char* buf, int len)
{
	int j = 0;
	int i = 0;
	for (; data[i] && j < len; i++) {
		while (data[i] == '%') {
			char hex[3];
			unsigned int value;
			char* error = NULL;
			hex[0] = data[i+1];
			if (!is_hex(hex[0])) break;
			hex[1] = data[i+2];
			if (!is_hex(hex[1])) break;
			hex[2] = '\0';
			value = strtoul(hex, NULL, 16);
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

int
server_download(struct http_request* req)
{
	char path[1024], header_buf[1024];
	char *ptr, *file_name, *ext;
	const char* mime_ptr;
	int fd, mime_id, header_len;
	size_t length;
	FILE *f;

	ptr = strstr(req->uri, "/download/");
	if (!ptr) {
		return -1;
	}
	ptr += sizeof("/download/") - 1;
	file_name = strchr(ptr, '/');
	if (!file_name)
		return -1;
	*file_name = '\0';
	*file_name = '/';
	if ((file_name[1] == '.' && file_name[2] == '.') ||
	    strchr(file_name+1, '/'))
		return -1;
	file_name++;
	ptr -= sizeof("/download/") - 2;
	format_path(ptr, path, sizeof(path));
	fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
	f = fdopen(fd, "rb");
	fseek(f, 0, SEEK_END);
	length = ftell(f);
	fseek(f, 0, SEEK_SET);
	req->length = length;
#ifdef __CYGWIN__
	fclose(f);
	fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
#endif
	req->data = fd;
	/* mime */
	ext = strrchr(file_name, '.');
	mime_id = !ext?-1:mime_from_extension(ext);
	mime_ptr = ((mime_id==-1)?"application/octet-stream":mime[mime_id]);
	/* header */
	header_len = snprintf(header_buf, sizeof(header_buf),
			      header, length, mime_ptr);
	send(req->socket, header_buf, header_len, 0);
	return 0;
}

int
server_send(struct http_request* req)
{
#ifndef HAS_SENDFILE
	char packet[32768];
#else
	off_t offset = req->sent;
#endif
	size_t to_send;
	int ret;

	if (req->data < 0 || req->socket < 0) return -1;
	to_send = req->length - req->sent;
	if (to_send > 32768) to_send = 32768;
#ifndef HAS_SENDFILE
	ret = read(req->data, packet, to_send);
	ret = send(req->socket, packet, ret, 0);
	req->sent += ret;
#elif __FreeBSD__
	ret = sendfile(req->data, req->socket, offset,
		       to_send, NULL, &offset, 0);
	if (!ret) ret = 1;
	req->sent += offset;
#else
	ret = sendfile(req->socket, req->data, &offset, to_send);
	req->sent = offset;
#endif

	if (ret <= 0) return -1;
	if (req->sent >= req->length) return 0;
	return 1;
}

int
server_serve(struct http_request* req)
{
	int hash;
	size_t bytes, l;
	struct file *file;
	char packet[4096];

	if (req->method == GET &&
	    !strncmp(req->uri, "/download/", sizeof("/download/") - 1)) {
		if (!server_download(req)) return 200;
		else goto err_404;
	}
	if (req->method != GET) goto err_404;
	hash = fnv(req->uri, strnlen(req->uri, sizeof(req->uri))) %
		FILES_TABLE_SIZE;
	file = &files[hash];
	if (!file->length) {
err_404:;
		memset(packet, 0, sizeof(packet));
		l = snprintf(packet, sizeof(packet),
			     header, sizeof(data_404) - 1,
			     "text/html");
		if (l >= sizeof(packet)) {
			printf("packet buffer overflowing");
			return -1;
		}
		l += strlcpy(&packet[l], data_404, sizeof(packet) - l);
		send(req->socket, packet, l+1, 0);
		return 404;
	}
	bytes = 0;
	while (bytes < file->size) {
		int ret = send(req->socket, &file->data[bytes],
			       file->size - bytes, 0);
		if (ret <= 0) break;
		bytes += ret;
	}
	return 200;
}

int
server_init(int port)
{
#ifdef DEBUG
	struct linger sl;
#endif
	struct sockaddr_in addr;
	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener == -1) {
		printf("Failed to create socket\n");
		return -1;
	}
#ifdef DEBUG
	/* instant reset, useful for testing */
        sl.l_onoff = 1;
        sl.l_linger = 0;
        setsockopt(listener, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
#endif
#ifdef __sun
	signal(SIGPIPE, SIG_IGN);
#endif

	memset(&addr, 0, sizeof(addr));
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
	fflush(stdout); /* to print log in sfm on illumos */
	return 0;
}

int
server_accept(struct http_request* req)
{
	unsigned int len;
	int socket;

	memset(req, 0, sizeof(struct http_request));
	req->data = -1;
	len = sizeof(req->addr);
	socket = accept(listener, (struct sockaddr*)&req->addr, &len);
	if (socket == -1) {
		printf("Failed to accept socket\n");
		return -1;
	}
	req->socket = socket;
	return 0;
}

int
server_recv(struct http_request* req)
{
	char *data_ptr, *end;
	int bytes, blen;

	bytes = recv(req->socket,
		     (req->data > -1)?req->packet:&req->packet[req->size],
		     (req->data > -1)?sizeof(req->packet):
		     (sizeof(req->packet) - req->size), 0);
	if (bytes <= 0) return -1;
	if (!req->boundary_found) {
		char* ptr = strstr(&req->packet[req->size], "boundary=");
		if (ptr) {
			char* start = ptr + sizeof("boundary=");
			ptr = start;
			while (ptr++ && *ptr != '\r');
			strlcpy(req->boundary, start, ptr - start);
			req->boundary_found = 1;
		}
	}
	req->size += bytes;
	data_ptr = req->packet;
	end = NULL;
	blen = 0;
	if (req->boundary_found)
		blen = strnlen(req->boundary, sizeof(req->boundary));
	while (req->data < 0 && req->boundary_found) {
		char* ptr = strstr(req->packet, req->boundary);
		if (!ptr) break;
		ptr = strstr(ptr + blen, req->boundary);
		if (!ptr) break;
		req->content = ptr + strnlen(req->boundary,
					     sizeof(req->boundary));
		req->length = req->size - (req->content - req->packet);
		server_upload(req);
		end = strstr(req->packet + req->size - blen - 8,
			     req->boundary);
		data_ptr = strstr(req->content + 4, "\r\n\r\n") + 4;
		bytes = req->size - (data_ptr - req->packet);
		break;
	}
	if (req->data > -1) {
		char packet[4096];
		size_t size;
		if (!end && data_ptr == req->packet)
			end = strstr(data_ptr + bytes - blen - 8,
				     req->boundary);
		write(req->data, data_ptr,
		      end?(end - data_ptr - 4):bytes);
		if (!end) return 1;
		size = snprintf(packet, sizeof(packet), "%s%s",
				req->header, req->updata);
		bytes = 0;
		while ((size_t)bytes < size) {
			int ret = send(req->socket, &packet[bytes],
				       size - bytes, 0);
			if (ret <= 0) break;
			bytes += ret;
		}
		return 2;
	}
	if (!req->boundary_found &&
	    req->packet[req->size - 1] == '\n' &&
	    req->packet[req->size - 2] == '\r' &&
	    req->packet[req->size - 3] == '\n' &&
	    req->packet[req->size - 4] == '\r') {
		return 0;
	}
	return 1;
}

#include <poll.h>
#define MAX_REQUESTS 1024
#define TIMEOUT_SINCE_STARTED 1200000
#define TIMEOUT_SINCE_LAST 10000
struct http_request requests[MAX_REQUESTS];
struct pollfd fds[MAX_REQUESTS];
size_t requests_count = 0;

int
new_request()
{
	int new = 1;
	size_t i = 0;
	time_t now = time(NULL);
	for (; i < requests_count; i++) {
		if (requests[i].done ||
		    now - requests[i].started >= TIMEOUT_SINCE_STARTED ||
		    now - requests[i].last >= TIMEOUT_SINCE_LAST) {
			new = 0;
			break;
		}
	}
	if (new && i >= sizeof(requests)/sizeof(struct http_request) - 1)
		return -1;
	if (server_accept(&requests[i]))
		return -1;
	fds[i + 1].fd = requests[i].socket;
	fds[i + 1].events = POLLIN;
	requests[i].last = requests[i].started = time(NULL);
	if (new)
		requests_count++;
	return 0;
}

void print_req(struct http_request* req, int code) {
#ifdef NO_PROXY
	uint8_t *ptr;
	print_now();
	ptr = (uint8_t*)&req->addr.sin_addr.s_addr;
	printf("%d.%d.%d.%d, %s, requested %s [%d]\n",
	       ptr[0], ptr[1], ptr[2], ptr[3],
	       req->useragent, req->uri, code);
#else
	print_now();
	printf("%s, %s, requested %s [%d]\n",
	       req->xrealip, req->useragent, req->uri, code);
#endif
	fflush(stdout); /* to print log in sfm on illumos */
}

int
server_thread()
{
	size_t i;
	memset(requests, 0, sizeof(requests));
	for (i = 1; i < sizeof(fds)/sizeof(struct pollfd); i++) {
		fds[i].fd = -1;
		fds[i].events = POLLIN;
	}
	fds[0].fd = listener;
	fds[0].events = POLLIN;
	while (1) {
		int nfds, ready;
		size_t i;

		nfds = requests_count + 1;
		ready = poll(fds, nfds, -1);
		if (ready == -1) break;
		if (fds[0].revents == POLLIN && new_request()) {
			print_now();
			printf("Failed to accept client\n");
			fflush(stdout);
		}
		for (i = 0; i < requests_count; i++) {
			int ret = 0;
			struct http_request* req = &requests[i];
			switch (fds[i + 1].revents) {
			case 0:
				break;
			case POLLOUT:
				requests[i].last = time(NULL);
				if (req->length <= req->sent)
					goto clean;
send_data:;
				ret = server_send(req);
				if (ret == 0) {
					close(req->data);
					req->data = -1;
					continue;
				}
				if (ret == 1) continue;
				goto clean;
			case POLLIN:
				requests[i].last = time(NULL);
				ret = server_recv(req);
				if (ret == 1) continue;
				if (ret == 2) print_req(req, 200);
				if (ret == 0) {
					if (req->data > -1) {
						close(req->data);
						req->data = -1;
					}
					http_parse(req);
					print_req(req, server_serve(req));
					if (req->data > -1) {
						fds[i + 1].events = POLLOUT;
						goto send_data;
					}
				}
clean:
				if (req->data > -1) {
					close(req->data);
					req->data = -1;
				}

				close(req->socket);
				req->socket = -1;
				req->done = 1;
				if (i + 1 == requests_count)
					requests_count--;
				memset(&fds[i + 1], 0, sizeof(struct pollfd));
				fds[i + 1].fd = -1;
				fds[i + 1].events = POLLIN;
				break;
			default:
				fds[i + 1].fd = -1;
				fds[i + 1].events = POLLIN;
			}
		}
	}
	return 0;
}

int
server_stop()
{
	close(listener);
	return 0;
}
