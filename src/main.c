#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "server.h"
#include "sandbox.h"

int main(int argc, char* argv[]) {
	struct stat sb;
	int ret = stat("download", &sb);
	if ((ret && mkdir("download", 0700)) ||
	   (!ret && !S_ISDIR(sb.st_mode))) {
		printf("Failed to create download directory\n");
		return -1;
	}

	int port = 8080;
	if (argc > 1) {
		port = atoi(argv[1]);
		if (!port) port = 8080;
	}

	load_file("static/index.html", "/", "text/html");
	load_file("static/upload.html", "/upload", "text/html");
	load_file("static/favicon.ico", "/favicon.ico", "image/x-icon");
	sandbox_start();

	if (server_init(port)) {
		printf("Failed to initialize the server\n");
		return -1;
	}
	server_thread();
	server_stop();

	return 0;
}
