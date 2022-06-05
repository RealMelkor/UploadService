#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "server.h"

int main(int argc, char* argv[]) {
	int port = 8080;
	if (argc > 1) {
		port = atoi(argv[1]);
		if (!port) port = 8080;
	}

	load_file("static/index.html", "/");
	load_file("static/upload.html", "/upload");
	load_file("static/favicon.ico", "/favicon.ico");
	load_file("static/1.jpg", "/1.jpg");
	load_file("static/TesRja0bkXuu.gif", "/test.gif");
	if (server_init(port)) {
		printf("Failed to initialize the server\n");
		return -1;
	}
	server_thread();
	server_stop();

	return 0;
}
