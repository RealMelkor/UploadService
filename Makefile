SHELL = /bin/sh

PREFIX = /usr/local
CFLAGS = -O2 -Wall -Wpedantic -Wextra
CC = cc
SRC = src/main.c src/parser.c src/server.c src/sandbox.c

upload: src/*
	${CC} ${SRC} ${CFLAGS} -o $@

install:
	cp upload ${PREFIX}/bin
	chmod 755 ${PREFIX}/bin/upload

uninstall:
	rm ${PREFIX}/bin/upload

clean:
	rm -f upload
