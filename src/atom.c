/* apk_atom.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2020 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "apk_atom.h"

apk_blob_t apk_atom_null = {0,""};

struct apk_atom_hashnode {
	struct hlist_node hash_node;
	apk_blob_t blob;
};

static apk_blob_t atom_hash_get_key(apk_hash_item item)
{
	return ((struct apk_atom_hashnode *) item)->blob;
}

static struct apk_hash_ops atom_ops = {
	.node_offset = offsetof(struct apk_atom_hashnode, hash_node),
	.get_key = atom_hash_get_key,
	.hash_key = apk_blob_hash,
	.compare = apk_blob_compare,
};

void apk_atom_init(struct apk_atom_pool *atoms)
{
	apk_balloc_init(&atoms->ba, 64*1024);
	apk_hash_init(&atoms->hash, &atom_ops, 10000);
}

void apk_atom_free(struct apk_atom_pool *atoms)
{
	apk_hash_free(&atoms->hash);
	apk_balloc_destroy(&atoms->ba);
}

apk_blob_t *apk_atom_get(struct apk_atom_pool *atoms, apk_blob_t blob, int duplicate)
{
	struct apk_atom_hashnode *atom;
	unsigned long hash = apk_hash_from_key(&atoms->hash, blob);

	if (blob.len < 0 || !blob.ptr) return &apk_atom_null;

	atom = (struct apk_atom_hashnode *) apk_hash_get_hashed(&atoms->hash, blob, hash);
	if (atom) return &atom->blob;

	if (duplicate) {
		char *ptr;
		atom = apk_balloc_new_extra(&atoms->ba, struct apk_atom_hashnode, blob.len + duplicate - 1);
		ptr = (char*) (atom + 1);
		memcpy(ptr, blob.ptr, blob.len);
		if (duplicate > 1) ptr[blob.len] = 0;
		atom->blob = APK_BLOB_PTR_LEN(ptr, blob.len);
	} else {
		atom = apk_balloc_new(&atoms->ba, struct apk_atom_hashnode);
		atom->blob = blob;
	}
	apk_hash_insert_hashed(&atoms->hash, atom, hash);
	return &atom->blob;
}
