#include_next <string.h>

#ifdef NEED_MEMRCHR
extern void *memrchr(const void *m, int c, size_t n);
#endif
