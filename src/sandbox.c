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
#elif __linux__
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#if ENABLE_LANDLOCK || (!defined(DISABLE_LANDLOCK) && __has_include(<linux/landlock.h>))
	#include <linux/landlock.h>
	#define ENABLE_LANDLOCK
#endif

// --------------
// copied from : https://roy.marples.name/git/dhcpcd/blob/HEAD:/src/privsep-linux.c
#define SC_ALLOW_(nr)                                            \
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1),   \
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
#define SC_ALLOW(nr)						\
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##nr, 0, 1),	\
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
#define SC_ALLOW_ARG(_nr, _arg, _val)						\
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (_nr), 0, 6),			\
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS,					\
	    offsetof(struct seccomp_data, args[(_arg)]) + SC_ARG_LO),		\
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,					\
	    ((_val) & 0xffffffff), 0, 3),					\
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS,					\
	    offsetof(struct seccomp_data, args[(_arg)]) + SC_ARG_HI),		\
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,					\
	    (((uint32_t)((uint64_t)(_val) >> 32)) & 0xffffffff), 0, 1),		\
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),				\
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS,					\
	    offsetof(struct seccomp_data, nr))
// --------------

struct sock_filter filter[] = {
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
	    (offsetof(struct seccomp_data, arch))),
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
        SC_ALLOW(fstat),
        SC_ALLOW(stat),
	SC_ALLOW(setsockopt),
	SC_ALLOW(accept),
	SC_ALLOW(listen),
	SC_ALLOW(bind),
	SC_ALLOW(mkdir),
	SC_ALLOW(read),
	SC_ALLOW(write),
        SC_ALLOW(readv),
        SC_ALLOW(writev),
        SC_ALLOW(open),
	SC_ALLOW(openat),
	SC_ALLOW(ioctl),
	SC_ALLOW(close),
	SC_ALLOW(exit),
	SC_ALLOW(exit_group),
	SC_ALLOW(futex),
	SC_ALLOW(newfstatat),
	SC_ALLOW(fcntl),
	SC_ALLOW(lseek),
	SC_ALLOW(mprotect),
	SC_ALLOW(pread64),
	SC_ALLOW(sendto),
	SC_ALLOW(recvfrom),
	SC_ALLOW(socket),
        SC_ALLOW(getsockopt),
	SC_ALLOW(poll),
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
};

#ifdef ENABLE_LANDLOCK
static inline int landlock_create_ruleset(const struct landlock_ruleset_attr *attr,
					  size_t size, uint32_t flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
static inline int landlock_add_rule(int ruleset_fd, enum landlock_rule_type type,
				    const void *attr, uint32_t flags)
{
	return syscall(__NR_landlock_add_rule, ruleset_fd, type, attr, flags);
}
static inline int landlock_restrict_self(int ruleset_fd, __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
int landlock_unveil(int landlock_fd, int fd, int perms)
{
	struct landlock_path_beneath_attr attr = {
		.allowed_access = perms,
		.parent_fd = fd
	};
	int ret = landlock_add_rule(landlock_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
	int err = errno;
	close(attr.parent_fd);
	errno = err;
	return ret;
}
#include <fcntl.h>
int landlock_unveil_path(int landlock_fd, const char* path, int perms) {
	int fd = open(path, 0);
	if (fd < 0) return -1;
	int ret = landlock_unveil(landlock_fd, fd, perms);
	return ret;
}
int landlock_init() {
	struct landlock_ruleset_attr attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
				     LANDLOCK_ACCESS_FS_WRITE_FILE,
	};
	return landlock_create_ruleset(&attr, sizeof(attr), 0);
}
int landlock_apply(int fd)
{
	int ret = landlock_restrict_self(fd, 0);
	int err = errno;
	close(fd);
	errno = err;
	return ret;
}
extern char config_path[1024];
extern char download_path[1024];
#endif

int sandbox_start() {
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		printf("PR_SET_NO_NEW_PRIVS failed\n");
		return -1;
	}
#ifdef ENABLE_LANDLOCK
	int llfd = landlock_init();
	if (llfd < 0) {
		printf("Failed to initialize landlock : %s\n", strerror(errno));
		printf("The filesystem won't be hidden from the program\n");
		goto skip_landlock;
	}
	int download = landlock_unveil_path(llfd, "download",
					LANDLOCK_ACCESS_FS_READ_FILE |
					LANDLOCK_ACCESS_FS_WRITE_FILE
					);
	if (download) {
		printf("landlock, failed to unveil : %s\n", strerror(errno));
		return -1;
	}
	if (landlock_apply(llfd)) {
		printf("landlock, failed to restrict process : %s\n", strerror(errno));
		return -1;
	}
skip_landlock:;
#endif
        struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof (filter[0])),
		.filter = filter,
        };
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0)) {
		printf("Failed to enable seccomp\n");
		return -1;
	}
	return 0;
}
#else
int sandbox_start() {
	printf("No sandbox available on your system\n");
	return 0;
}
#endif
