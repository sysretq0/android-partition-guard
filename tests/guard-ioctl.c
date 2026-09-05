// guard-ioctl: raw-syscall BLKDISCARD issuer for the guard race test.
// No libc, no sysroot needed: aarch64 syscalls via inline asm.
// Usage: guard-ioctl /dev/block/by-name/nvram
// Exit: 0 ioctl issued (or denied), 1 usage/error.
// Build: clang --target=aarch64-linux-gnu -nostdlib -static -O2 -o guard-ioctl guard-ioctl.c
typedef unsigned long u64;
typedef unsigned int u32;

#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_CLOEXEC 02000000
#define __NR_openat 56
#define __NR_ioctl 29
#define __NR_close 57
#define __NR_exit_group 94
#define BLKDISCARD 0x1277

static long raw_syscall6(long n, long a, long b, long c, long d, long e,
			 long f)
{
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d;
	register long x4 __asm__("x4") = e;
	register long x5 __asm__("x5") = f;
	register long x8 __asm__("x8") = n;
	__asm__ volatile("svc #0"
			 : "+r"(x0)
			 : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
			 : "memory", "cc");
	return x0;
}

static long raw_syscall3(long n, long a, long b, long c)
{
	return raw_syscall6(n, a, b, c, 0, 0, 0);
}

struct fstrim_range {
	u64 start;
	u64 len;
};

void _start(void)
{
	/* locate argv: sp -> argc, argv... (aarch64 ABI) */
	long *sp;
	long argc;
	char **argv;
	__asm__ volatile("mov %0, sp" : "=r"(sp));
	argc = sp[0];
	argv = (char **)&sp[1];
	if (argc != 2)
		raw_syscall3(__NR_exit_group, 1, 0, 0);

	long fd = raw_syscall6(__NR_openat, AT_FDCWD, (long)argv[1],
			       O_RDONLY | O_CLOEXEC, 0, 0, 0);
	if (fd < 0)
		raw_syscall3(__NR_exit_group, 1, 0, 0);

	struct fstrim_range r;
	r.start = 0;
	r.len = 4096;
	/* Return value ignored: EPERM (guard) and success both exit 0.
	 * The verdict is read from the guard's denied counter + dmesg. */
	raw_syscall3(__NR_ioctl, fd, BLKDISCARD, (long)&r);
	raw_syscall3(__NR_close, fd, 0, 0);
	raw_syscall3(__NR_exit_group, 0, 0, 0);
	__builtin_unreachable();
}
