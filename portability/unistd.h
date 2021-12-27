#include_next <unistd.h>

#ifdef NEED_PIPE2
int pipe2(int pipefd[2], int flags);
#endif
