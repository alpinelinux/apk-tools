#include_next <stdlib.h>

#ifdef NEED_QSORT_R
void qsort_r(void *base, size_t nmemb, size_t size,
	int (*compar)(const void *, const void *, void *),
	void *arg);
#endif
