/* apk_atom.h - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2020 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef APK_ATOM_H
#define APK_ATOM_H

#include "apk_hash.h"
#include "apk_blob.h"
#include "apk_balloc.h"

extern apk_blob_t apk_atom_null;

struct apk_atom_pool {
	struct apk_balloc ba;
	struct apk_hash hash;
};

void apk_atom_init(struct apk_atom_pool *);
void apk_atom_free(struct apk_atom_pool *);
apk_blob_t *apk_atom_get(struct apk_atom_pool *atoms, apk_blob_t blob, int duplicate);

static inline apk_blob_t *apk_atomize(struct apk_atom_pool *atoms, apk_blob_t blob) {
	return apk_atom_get(atoms, blob, 0);
}
static inline apk_blob_t *apk_atomize_dup(struct apk_atom_pool *atoms, apk_blob_t blob) {
	return apk_atom_get(atoms, blob, 1);
}
static inline apk_blob_t *apk_atomize_dup0(struct apk_atom_pool *atoms, apk_blob_t blob) {
	return apk_atom_get(atoms, blob, 2);
}

#endif
