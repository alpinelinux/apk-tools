#include_next <sys/mman.h>

#ifdef NEED_MEMFD_CREATE
# define memfd_create(name, flags) ({errno = ENOSYS; -1;})
#endif

#ifndef MFD_EXEC
# define MFD_EXEC		0x0010U
#endif
