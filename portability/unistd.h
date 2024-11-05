#include_next <unistd.h>

#ifdef NEED_PIPE2
int pipe2(int pipefd[2], int flags);
#endif

#ifdef NEED_FEXECVE
# define fexecve(fd, argv, envp) ({errno = ENOSYS; -1;})
#endif

#ifdef __APPLE__
# include <crt_externs.h>
# define environ (*_NSGetEnviron())
#endif
