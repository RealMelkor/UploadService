# UploadService

Simple http server written in ANSI C, allowing users to upload their files and
download them.

## Build instructions

UploadService doesn't have any dependencies, using the make command should
build the program.
Uncomment NO_SANDBOX in the Makefile to disable sandboxing.
Uncomment NO_PROXY in the Makefile to disable displaying the ip using XRealIP.

Tested on :
* Linux
* Illumos
* FreeBSD
* OpenBSD
* NetBSD
