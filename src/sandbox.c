#include "sandbox.h"
#include <unistd.h>
#include <stdio.h>

#ifdef __OpenBSD__
int sandbox_start() {
	unveil("download", "rwc");
	unveil(NULL, NULL);
	pledge("stdio inet rpath wpath cpath", NULL);
	return 0;
}
#else
int sandbox_start() {
	printf("No sandbox available on your system\n");
	return 0;
}
#endif
