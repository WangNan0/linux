#ifndef LINUX_VERSION_CODE
# error Need LINUX_VERSION_CODE
# error Example: for 4.2 kernel, put 'clang-opt="-DLINUX_VERSION_CODE=0x40200" into llvm section of ~/.perfconfig'
#endif

SEC("func=vfs_read file->f_mode")
int bpf_func__vfs_read(void *ctx, int err, unsigned long f_mode)
{
	return 1;
}
