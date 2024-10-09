#include_next <sys/mman.h>

#ifdef NEED_MEMFD_CREATE
int memfd_create(const char *, unsigned);
#endif
