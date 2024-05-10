#include_next <sys/random.h>
#include <sys/types.h>

#ifdef NEED_GETRANDOM
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
#endif
