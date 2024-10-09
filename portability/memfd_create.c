#include <errno.h>
#include <sys/mman.h>

int memfd_create(const char *, unsigned) {
	return -ENOSYS;
}
