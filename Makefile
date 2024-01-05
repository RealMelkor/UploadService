SHELL = /bin/sh

PREFIX = /usr/local

CFLAGS = -ansi -std=c89 -pedantic -Wall -Wextra \
	 -O2 -D_POSIX_C_SOURCE=200809L
CC = cc
# Uncomment to build on Illumos
#CFLAGS = -ansi -std=c89 -pedantic -O2 -Wall -Wextra -lsocket -lsendfile
#CC = gcc

SRC = src/main.c src/parser.c src/server.c src/sandbox.c src/strlcpy.c \
      -D_POSIX_C_SOURCE=200809L -DNO_PROXY #-DNO_SANDBOX

upload: src/*
	${CC} ${SRC} ${CFLAGS} -o $@

install:
	cp upload ${PREFIX}/bin
	chmod 755 ${PREFIX}/bin/upload

uninstall:
	rm ${PREFIX}/bin/upload

clean:
	rm -f upload
