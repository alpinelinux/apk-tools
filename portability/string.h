#include_next <string.h>

#ifdef NEED_MEMRCHR
extern void *memrchr(const void *m, int c, size_t n);
#endif

#ifdef NEED_STRCHRNUL
static inline char *strchrnul(const char *s, int c) {
	return strchr(s, c) ?: s + strlen(s);
}
#endif

#ifdef NEED_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t size);
#endif
