/* common.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "apk_defines.h"

static int *dummy_array = 0;

void *apk_array_resize(void *array, size_t new_size, size_t elem_size)
{
	size_t old_size;
	ssize_t diff;
	void *tmp;

	if (new_size == 0) {
		if (array != &dummy_array)
			free(array);
		return &dummy_array;
	}

	old_size = array ? *((size_t *) array) : 0;
	diff = new_size - old_size;

	if (array == &dummy_array)
		array = NULL;

	tmp = realloc(array, sizeof(size_t) + new_size * elem_size);
	if (diff > 0)
		memset(tmp + sizeof(size_t) + old_size * elem_size, 0,
		       diff * elem_size);
	*((size_t*) tmp) = new_size;

	return tmp;
}
