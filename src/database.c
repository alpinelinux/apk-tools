/* database.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <fnmatch.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/stat.h>

#ifdef __linux__
# include <mntent.h>
# include <sys/vfs.h>
# include <sys/mount.h>
# include <sys/statvfs.h>
# include <linux/magic.h>
#endif

#include "apk_defines.h"
#include "apk_arch.h"
#include "apk_package.h"
#include "apk_database.h"
#include "apk_applet.h"
#include "apk_ctype.h"
#include "apk_extract.h"
#include "apk_print.h"
#include "apk_tar.h"
#include "apk_adb.h"
#include "apk_fs.h"

enum {
	APK_DIR_FREE = 0,
	APK_DIR_REMOVE
};

static const char * const apkindex_tar_gz = "APKINDEX.tar.gz";
static const char * const apk_static_cache_dir = "var/cache/apk";
static const char * const apk_world_file = "etc/apk/world";
static const char * const apk_arch_file = "etc/apk/arch";
static const char * const apk_lock_file = "run/apk/db.lock";
static const char * const apk_legacy_lock_file = "lib/apk/db/lock";

static struct apk_db_acl *apk_default_acl_dir, *apk_default_acl_file;

struct install_ctx {
	struct apk_database *db;
	struct apk_package *pkg;
	struct apk_installed_package *ipkg;

	int script;
	char **script_args;
	unsigned int script_pending : 1;

	struct apk_db_dir_instance *diri;
	struct apk_extract_ctx ectx;

	apk_progress_cb cb;
	void *cb_ctx;
	size_t installed_size;

	struct hlist_node **diri_node;
	struct hlist_node **file_diri_node;
};

static mode_t apk_db_dir_get_mode(struct apk_database *db, mode_t mode)
{
	// in usermode, return mode that makes the file readable for user
	if (db->usermode) return mode | S_IWUSR | S_IXUSR;
	return mode;
}

static apk_blob_t apk_pkg_ctx(struct apk_package *pkg)
{
	return APK_BLOB_PTR_LEN(pkg->name->name, strlen(pkg->name->name)+1);
}

static apk_blob_t pkg_name_get_key(apk_hash_item item)
{
	return APK_BLOB_STR(((struct apk_name *) item)->name);
}

static void pkg_name_free(struct apk_name *name)
{
	apk_provider_array_free(&name->providers);
	apk_name_array_free(&name->rdepends);
	apk_name_array_free(&name->rinstall_if);
}

static const struct apk_hash_ops pkg_name_hash_ops = {
	.node_offset = offsetof(struct apk_name, hash_node),
	.get_key = pkg_name_get_key,
	.hash_key = apk_blob_hash,
	.compare = apk_blob_compare,
	.delete_item = (apk_hash_delete_f) pkg_name_free,
};

static apk_blob_t pkg_info_get_key(apk_hash_item item)
{
	return apk_pkg_hash_blob(item);
}

static unsigned long csum_hash(apk_blob_t csum)
{
	/* Checksum's highest bits have the most "randomness", use that
	 * directly as hash */
	if (csum.len >= sizeof(uint32_t))
		return get_unaligned32(csum.ptr);
	return 0;
}

static const struct apk_hash_ops pkg_info_hash_ops = {
	.node_offset = offsetof(struct apk_package, hash_node),
	.get_key = pkg_info_get_key,
	.hash_key = csum_hash,
	.compare = apk_blob_compare,
};

static apk_blob_t apk_db_dir_get_key(apk_hash_item item)
{
	struct apk_db_dir *dir = (struct apk_db_dir *) item;
	return APK_BLOB_PTR_LEN(dir->name, dir->namelen);
}

static const struct apk_hash_ops dir_hash_ops = {
	.node_offset = offsetof(struct apk_db_dir, hash_node),
	.get_key = apk_db_dir_get_key,
	.hash_key = apk_blob_hash,
	.compare = apk_blob_compare,
};

struct apk_db_file_hash_key {
	apk_blob_t dirname;
	apk_blob_t filename;
};

static unsigned long apk_db_file_hash_key(apk_blob_t _key)
{
	struct apk_db_file_hash_key *key = (struct apk_db_file_hash_key *) _key.ptr;

	return apk_blob_hash_seed(key->filename, apk_blob_hash(key->dirname));
}

static unsigned long apk_db_file_hash_item(apk_hash_item item)
{
	struct apk_db_file *dbf = (struct apk_db_file *) item;

	return apk_blob_hash_seed(APK_BLOB_PTR_LEN(dbf->name, dbf->namelen),
				  dbf->diri->dir->hash);
}

static int apk_db_file_compare_item(apk_hash_item item, apk_blob_t _key)
{
	struct apk_db_file *dbf = (struct apk_db_file *) item;
	struct apk_db_file_hash_key *key = (struct apk_db_file_hash_key *) _key.ptr;
	struct apk_db_dir *dir = dbf->diri->dir;
	int r;

	r = apk_blob_compare(key->filename,
			     APK_BLOB_PTR_LEN(dbf->name, dbf->namelen));
	if (r != 0)
		return r;

	r = apk_blob_compare(key->dirname,
			     APK_BLOB_PTR_LEN(dir->name, dir->namelen));
	return r;
}

static const struct apk_hash_ops file_hash_ops = {
	.node_offset = offsetof(struct apk_db_file, hash_node),
	.hash_key = apk_db_file_hash_key,
	.hash_item = apk_db_file_hash_item,
	.compare_item = apk_db_file_compare_item,
};

struct apk_name *apk_db_query_name(struct apk_database *db, apk_blob_t name)
{
	return (struct apk_name *) apk_hash_get(&db->available.names, name);
}

struct apk_name *apk_db_get_name(struct apk_database *db, apk_blob_t name)
{
	struct apk_name *pn;
	unsigned long hash = apk_hash_from_key(&db->available.names, name);

	pn = (struct apk_name *) apk_hash_get_hashed(&db->available.names, name, hash);
	if (pn != NULL)
		return pn;

	pn = apk_balloc_new_extra(&db->ba_names, struct apk_name, name.len+1);
	if (pn == NULL) return NULL;

	memset(pn, 0, sizeof *pn);
	memcpy(pn->name, name.ptr, name.len);
	pn->name[name.len] = 0;
	apk_provider_array_init(&pn->providers);
	apk_name_array_init(&pn->rdepends);
	apk_name_array_init(&pn->rinstall_if);
	apk_hash_insert_hashed(&db->available.names, pn, hash);
	db->sorted_names = 0;

	return pn;
}

static int cmp_provider(const void *a, const void *b)
{
	const struct apk_provider *pa = a, *pb = b;
	return apk_pkg_cmp_display(pa->pkg, pb->pkg);
}

struct apk_provider_array *apk_name_sorted_providers(struct apk_name *name)
{
	if (!name->providers_sorted) {
		apk_array_qsort(name->providers, cmp_provider);
		name->providers_sorted = 0;
	}
	return name->providers;
}

static struct apk_db_acl *__apk_db_acl_atomize(struct apk_database *db, mode_t mode, uid_t uid, gid_t gid, uint8_t hash_len, const uint8_t *hash)
{
	struct {
		struct apk_db_acl acl;
		uint8_t digest[APK_DIGEST_LENGTH_MAX];
	} data;
	apk_blob_t *b;

	data.acl = (struct apk_db_acl) { .mode = mode & 07777, .uid = uid, .gid = gid, .xattr_hash_len = hash_len };
	if (hash_len) memcpy(data.digest, hash, hash_len);

	b = apk_atomize_dup(&db->atoms, APK_BLOB_PTR_LEN((char*) &data, sizeof(data.acl) + hash_len));
	return (struct apk_db_acl *) b->ptr;
}

static struct apk_db_acl *apk_db_acl_atomize(struct apk_database *db, mode_t mode, uid_t uid, gid_t gid)
{
	return __apk_db_acl_atomize(db, mode, uid, gid, 0, 0);
}

static struct apk_db_acl *apk_db_acl_atomize_digest(struct apk_database *db, mode_t mode, uid_t uid, gid_t gid, const struct apk_digest *dig)
{
	return __apk_db_acl_atomize(db, mode, uid, gid, dig->len, dig->data);
}

static int apk_db_dir_mkdir(struct apk_database *db, struct apk_fsdir *d, struct apk_db_acl *acl)
{
	if (db->ctx->flags & APK_SIMULATE) return 0;
	return apk_fsdir_create(d, apk_db_dir_get_mode(db, acl->mode), acl->uid, acl->gid);
}

void apk_db_dir_prepare(struct apk_database *db, struct apk_db_dir *dir, struct apk_db_acl *expected_acl, struct apk_db_acl *new_acl)
{
	struct apk_fsdir d;

	if (dir->namelen == 0) return;
	if (dir->created) return;
	dir->created = 1;

	apk_fsdir_get(&d, APK_BLOB_PTR_LEN(dir->name, dir->namelen), db->extract_flags, db->ctx, APK_BLOB_NULL);
	if (!expected_acl) {
		/* Directory should not exist. Create it. */
		if (apk_db_dir_mkdir(db, &d, new_acl) == 0)
			dir->permissions_ok = 1;
		return;
	}

	switch (apk_fsdir_check(&d, apk_db_dir_get_mode(db, expected_acl->mode), expected_acl->uid, expected_acl->gid)) {
	case -ENOENT:
		if (apk_db_dir_mkdir(db, &d, new_acl) == 0)
			dir->permissions_ok = 1;
		break;
	case 0:
		dir->permissions_ok = 1;
		break;
	case APK_FS_DIR_MODIFIED:
	default:
		break;
	}
}

void apk_db_dir_unref(struct apk_database *db, struct apk_db_dir *dir, int rmdir_mode)
{
	if (--dir->refs > 0) return;
	db->installed.stats.dirs--;
	apk_protected_path_array_free(&dir->protected_paths);
	list_del(&dir->diris);
	if (dir->namelen != 0) {
		if (rmdir_mode == APK_DIR_REMOVE) {
			dir->modified = 1;
			if (!(db->ctx->flags & APK_SIMULATE)) {
				struct apk_fsdir d;
				apk_fsdir_get(&d, APK_BLOB_PTR_LEN(dir->name, dir->namelen),
					      db->extract_flags, db->ctx, APK_BLOB_NULL);
				apk_fsdir_delete(&d);
			}
		}
		apk_db_dir_unref(db, dir->parent, rmdir_mode);
		dir->parent = NULL;
	}
	dir->created = dir->permissions_ok = 0;
}

struct apk_db_dir *apk_db_dir_ref(struct apk_db_dir *dir)
{
	dir->refs++;
	return dir;
}

struct apk_db_dir *apk_db_dir_query(struct apk_database *db,
				    apk_blob_t name)
{
	return (struct apk_db_dir *) apk_hash_get(&db->installed.dirs, name);
}

struct apk_db_dir *apk_db_dir_get(struct apk_database *db, apk_blob_t name)
{
	struct apk_db_dir *dir;
	struct apk_protected_path_array *ppaths;
	struct apk_protected_path *ppath;
	apk_blob_t bparent;
	unsigned long hash = apk_hash_from_key(&db->installed.dirs, name);
	char *relative_name;

	if (name.len && name.ptr[name.len-1] == '/') name.len--;

	dir = (struct apk_db_dir *) apk_hash_get_hashed(&db->installed.dirs, name, hash);
	if (dir != NULL && dir->refs) return apk_db_dir_ref(dir);
	if (dir == NULL) {
		dir = apk_balloc_new_extra(&db->ba_files, struct apk_db_dir, name.len+1);
		memset(dir, 0, sizeof *dir);
		dir->rooted_name[0] = '/';
		memcpy(dir->name, name.ptr, name.len);
		dir->name[name.len] = 0;
		dir->namelen = name.len;
		dir->hash = hash;
		apk_protected_path_array_init(&dir->protected_paths);
		apk_hash_insert_hashed(&db->installed.dirs, dir, hash);
	}

	db->installed.stats.dirs++;
	dir->refs = 1;
	list_init(&dir->diris);

	if (name.len == 0) {
		dir->parent = NULL;
		dir->has_protected_children = 1;
		ppaths = NULL;
	} else if (apk_blob_rsplit(name, '/', &bparent, NULL)) {
		dir->parent = apk_db_dir_get(db, bparent);
		dir->protect_mode = dir->parent->protect_mode;
		dir->has_protected_children = !apk_protect_mode_none(dir->protect_mode);
		ppaths = dir->parent->protected_paths;
	} else {
		dir->parent = apk_db_dir_get(db, APK_BLOB_NULL);
		ppaths = db->protected_paths;
	}

	if (ppaths == NULL)
		return dir;

	relative_name = strrchr(dir->rooted_name, '/') + 1;
	foreach_array_item(ppath, ppaths) {
		char *slash = strchr(ppath->relative_pattern, '/');
		if (slash != NULL) {
			*slash = 0;
			if (fnmatch(ppath->relative_pattern, relative_name, FNM_PATHNAME) != 0) {
				*slash = '/';
				continue;
			}
			*slash = '/';

			apk_protected_path_array_add(&dir->protected_paths, (struct apk_protected_path) {
				.relative_pattern = slash + 1,
				.protect_mode = ppath->protect_mode,
			});
		} else {
			if (fnmatch(ppath->relative_pattern, relative_name, FNM_PATHNAME) != 0)
				continue;

			dir->protect_mode = ppath->protect_mode;
		}
		dir->has_protected_children |= !apk_protect_mode_none(ppath->protect_mode);
	}

	return dir;
}

static struct apk_db_dir_instance *apk_db_diri_new(struct apk_database *db,
						   struct apk_package *pkg,
						   apk_blob_t name,
						   struct hlist_node ***after)
{
	struct apk_db_dir_instance *diri;

	diri = calloc(1, sizeof(struct apk_db_dir_instance));
	if (diri != NULL) {
		struct apk_db_dir *dir = apk_db_dir_get(db, name);
		list_init(&diri->dir_diri_list);
		list_add(&diri->dir_diri_list, &dir->diris);
		hlist_add_after(&diri->pkg_dirs_list, *after);
		*after = &diri->pkg_dirs_list.next;
		diri->dir = dir;
		diri->pkg = pkg;
		diri->acl = apk_default_acl_dir;
	}

	return diri;
}

void apk_db_dir_update_permissions(struct apk_database *db, struct apk_db_dir_instance *diri)
{
	struct apk_db_dir *dir = diri->dir;
	struct apk_db_acl *acl = diri->acl;
	struct apk_fsdir d;
	char buf[APK_EXTRACTW_BUFSZ];
	int r;

	if (!dir->permissions_ok) return;
	if (db->ctx->flags & APK_SIMULATE) return;

	dir->modified = 1;
	apk_fsdir_get(&d, APK_BLOB_PTR_LEN(dir->name, dir->namelen), db->extract_flags, db->ctx, APK_BLOB_NULL);
	r = apk_fsdir_update_perms(&d, apk_db_dir_get_mode(db, acl->mode), acl->uid, acl->gid);
	if (r != 0) {
		apk_warn(&db->ctx->out, "failed to update directory %s: %s", dir->name, apk_extract_warning_str(r, buf, sizeof buf));
		db->num_dir_update_errors++;
	}
}

static void apk_db_dir_apply_diri_permissions(struct apk_database *db, struct apk_db_dir_instance *diri)
{
	struct apk_db_dir *dir = diri->dir;
	struct apk_db_acl *acl = diri->acl;

	if (dir->owner && apk_pkg_replaces_dir(dir->owner->pkg, diri->pkg) != APK_PKG_REPLACES_YES)
		return;

	// Check if the ACL changed and the directory needs update
	if (dir->owner && dir->owner->acl != acl) apk_db_dir_update_permissions(db, diri);
	dir->owner = diri;
}

static void apk_db_diri_free(struct apk_database *db,
			     struct apk_db_dir_instance *diri,
			     int rmdir_mode)
{
	list_del(&diri->dir_diri_list);
	if (rmdir_mode == APK_DIR_REMOVE && diri->dir->owner == diri) {
		// Walk the directory instance to determine new owner
		struct apk_db_dir *dir = diri->dir;
		struct apk_db_dir_instance *di;
		dir->owner = NULL;
		list_for_each_entry(di, &dir->diris, dir_diri_list) {
			if (dir->owner == NULL ||
			    apk_pkg_replaces_dir(dir->owner->pkg, di->pkg) == APK_PKG_REPLACES_YES)
				dir->owner = di;
		}
		if (dir->owner) apk_db_dir_update_permissions(db, dir->owner);
	}
	apk_db_dir_unref(db, diri->dir, rmdir_mode);
	free(diri);
}

struct apk_db_file *apk_db_file_query(struct apk_database *db,
				      apk_blob_t dir,
				      apk_blob_t name)
{
	struct apk_db_file_hash_key key;

	if (dir.len && dir.ptr[dir.len-1] == '/')
		dir.len--;

	key = (struct apk_db_file_hash_key) {
		.dirname = dir,
		.filename = name,
	};

	return (struct apk_db_file *) apk_hash_get(&db->installed.files,
						   APK_BLOB_BUF(&key));
}

static struct apk_db_file *apk_db_file_new(struct apk_database *db,
					   struct apk_db_dir_instance *diri,
					   apk_blob_t name,
					   struct hlist_node ***after)
{
	struct apk_db_file *file;

	file = apk_balloc_new_extra(&db->ba_files, struct apk_db_file, name.len+1);
	if (file == NULL) return NULL;

	memset(file, 0, sizeof(*file));
	memcpy(file->name, name.ptr, name.len);
	file->name[name.len] = 0;
	file->namelen = name.len;
	file->diri = diri;
	file->acl = apk_default_acl_file;
	hlist_add_after(&file->diri_files_list, *after);
	*after = &file->diri_files_list.next;

	return file;
}

static struct apk_db_file *apk_db_file_get(struct apk_database *db,
					   struct apk_db_dir_instance *diri,
					   apk_blob_t name,
					   struct hlist_node ***after)
{
	struct apk_db_file *file;
	struct apk_db_file_hash_key key;
	struct apk_db_dir *dir = diri->dir;
	unsigned long hash;

	key = (struct apk_db_file_hash_key) {
		.dirname = APK_BLOB_PTR_LEN(dir->name, dir->namelen),
		.filename = name,
	};

	hash = apk_blob_hash_seed(name, dir->hash);
	file = (struct apk_db_file *) apk_hash_get_hashed(
		&db->installed.files, APK_BLOB_BUF(&key), hash);
	if (file != NULL)
		return file;

	file = apk_db_file_new(db, diri, name, after);
	apk_hash_insert_hashed(&db->installed.files, file, hash);
	db->installed.stats.files++;

	return file;
}

static void add_name_to_array(struct apk_name *name, struct apk_name_array **a)
{
	struct apk_name **n;

	foreach_array_item(n, *a)
		if (*n == name) return;
	apk_name_array_add(a, name);
}

static void apk_db_pkg_rdepends(struct apk_database *db, struct apk_package *pkg)
{
	struct apk_name *rname;
	struct apk_dependency *d;

	foreach_array_item(d, pkg->depends) {
		rname = d->name;
		rname->is_dependency |= !apk_dep_conflict(d);
		add_name_to_array(pkg->name, &rname->rdepends);
	}
	foreach_array_item(d, pkg->install_if) {
		rname = d->name;
		add_name_to_array(pkg->name, &rname->rinstall_if);
	}
}

static int apk_db_parse_istream(struct apk_database *db, struct apk_istream *is, int (*cb)(struct apk_database *, apk_blob_t))
{
	apk_blob_t token = APK_BLOB_STRLIT("\n"), line;
	int r;

	if (IS_ERR(is)) return PTR_ERR(is);
	while (apk_istream_get_delim(is, token, &line) == 0) {
		r = cb(db, line);
		if (r < 0) {
			apk_istream_error(is, r);
			break;
		}
	}
	return apk_istream_close(is);
}

static int apk_db_add_arch(struct apk_database *db, apk_blob_t arch)
{
	apk_blob_t **item, *atom = apk_atomize_dup(&db->atoms, apk_blob_trim(arch));
	foreach_array_item(item, db->arches)
		if (*item == atom) return 0;
	apk_blobptr_array_add(&db->arches, atom);
	return 0;
}

bool apk_db_arch_compatible(struct apk_database *db, apk_blob_t *arch)
{
	apk_blob_t **item;
	foreach_array_item(item, db->arches)
		if (*item == arch) return true;
	return db->noarch == arch;
}

struct apk_package *apk_db_pkg_add(struct apk_database *db, struct apk_package_tmpl *tmpl)
{
	struct apk_package *pkg = &tmpl->pkg, *idb;
	struct apk_dependency *dep;

	if (!pkg->name || !pkg->version || tmpl->id.len < APK_DIGEST_LENGTH_SHA1) return NULL;

	// Set as "cached" if installing from specified file
	if (pkg->filename_ndx) pkg->repos |= BIT(APK_REPOSITORY_CACHED);

	idb = apk_hash_get(&db->available.packages, APK_BLOB_PTR_LEN((char*)tmpl->id.data, APK_DIGEST_LENGTH_SHA1));
	if (idb == NULL) {
		idb = apk_balloc_new_extra(&db->ba_pkgs, struct apk_package, tmpl->id.len);
		memcpy(idb, pkg, sizeof *pkg);
		memcpy(idb->digest, tmpl->id.data, tmpl->id.len);
		idb->digest_alg = tmpl->id.alg;
		if (idb->digest_alg == APK_DIGEST_SHA1 && idb->ipkg && idb->ipkg->sha256_160)
			idb->digest_alg = APK_DIGEST_SHA256_160;
		idb->ipkg = NULL;
		idb->depends = apk_deps_bclone(pkg->depends, &db->ba_deps);
		idb->install_if = apk_deps_bclone(pkg->install_if, &db->ba_deps);
		idb->provides = apk_deps_bclone(pkg->provides, &db->ba_deps);

		apk_hash_insert(&db->available.packages, idb);
		apk_provider_array_add(&idb->name->providers, APK_PROVIDER_FROM_PACKAGE(idb));
		foreach_array_item(dep, idb->provides)
			apk_provider_array_add(&dep->name->providers, APK_PROVIDER_FROM_PROVIDES(idb, dep));
		if (db->open_complete)
			apk_db_pkg_rdepends(db, idb);
	} else {
		idb->repos |= pkg->repos;
		if (!idb->filename_ndx) idb->filename_ndx = pkg->filename_ndx;
	}
	if (idb->ipkg == NULL && pkg->ipkg != NULL) {
		struct apk_db_dir_instance *diri;
		struct hlist_node *n;

		hlist_for_each_entry(diri, n, &pkg->ipkg->owned_dirs, pkg_dirs_list)
			diri->pkg = idb;
		idb->ipkg = pkg->ipkg;
		idb->ipkg->pkg = idb;
		pkg->ipkg = NULL;
	}
	apk_pkgtmpl_reset(tmpl);
	return idb;
}

static int apk_pkg_format_cache_pkg(apk_blob_t to, struct apk_package *pkg)
{
	/* pkgname-1.0_alpha1.12345678.apk */
	apk_blob_push_blob(&to, APK_BLOB_STR(pkg->name->name));
	apk_blob_push_blob(&to, APK_BLOB_STR("-"));
	apk_blob_push_blob(&to, *pkg->version);
	apk_blob_push_blob(&to, APK_BLOB_STR("."));
	apk_blob_push_hexdump(&to, APK_BLOB_PTR_LEN((char *) pkg->digest, APK_CACHE_CSUM_BYTES));
	apk_blob_push_blob(&to, APK_BLOB_STR(".apk"));
	apk_blob_push_blob(&to, APK_BLOB_PTR_LEN("", 1));
	if (APK_BLOB_IS_NULL(to))
		return -ENOBUFS;
	return 0;
}

int apk_repo_format_cache_index(apk_blob_t to, struct apk_repository *repo)
{
	/* APKINDEX.12345678.tar.gz */
	apk_blob_push_blob(&to, APK_BLOB_STR("APKINDEX."));
	apk_blob_push_hexdump(&to, APK_BLOB_PTR_LEN((char *) repo->hash.data, APK_CACHE_CSUM_BYTES));
	apk_blob_push_blob(&to, APK_BLOB_STR(".tar.gz"));
	apk_blob_push_blob(&to, APK_BLOB_PTR_LEN("", 1));
	if (APK_BLOB_IS_NULL(to))
		return -ENOBUFS;
	return 0;
}

int apk_repo_format_real_url(apk_blob_t *default_arch, struct apk_repository *repo,
			     struct apk_package *pkg, char *buf, size_t len,
			     struct apk_url_print *urlp)
{
	apk_blob_t uri = APK_BLOB_STR(repo->url);
	apk_blob_t arch;
	int r = -EINVAL;

	if (pkg && pkg->arch) arch = *pkg->arch;
	else arch = *default_arch;

	if (apk_blob_ends_with(uri, APK_BLOB_STR(".adb"))) {
		if (pkg != NULL) {
			apk_blob_rsplit(uri, '/', &uri, NULL);
			r = apk_fmt(buf, len, BLOB_FMT "/" PKG_FILE_FMT,
				BLOB_PRINTF(uri), PKG_FILE_PRINTF(pkg));
		} else {
			r = apk_fmt(buf, len, BLOB_FMT, BLOB_PRINTF(uri));
		}
	} else {
		while (uri.len && uri.ptr[uri.len-1] == '/') uri.len--;
		if (pkg != NULL)
			r = apk_fmt(buf, len, BLOB_FMT "/" BLOB_FMT "/" PKG_FILE_FMT,
				BLOB_PRINTF(uri), BLOB_PRINTF(arch), PKG_FILE_PRINTF(pkg));
		else
			r = apk_fmt(buf, len, BLOB_FMT "/" BLOB_FMT "/%s",
				BLOB_PRINTF(uri), BLOB_PRINTF(arch), apkindex_tar_gz);
	}
	if (r < 0) return r;
	if (urlp) apk_url_parse(urlp, buf);
	return 0;
}

int apk_repo_format_item(struct apk_database *db, struct apk_repository *repo, struct apk_package *pkg,
			 int *fd, char *buf, size_t len)
{
	if (repo->url == db->repos[APK_REPOSITORY_CACHED].url) {
		if (db->cache_fd < 0) return db->cache_fd;
		*fd = db->cache_fd;
		return apk_pkg_format_cache_pkg(APK_BLOB_PTR_LEN(buf, len), pkg);
	}

	*fd = AT_FDCWD;
	return apk_repo_format_real_url(db->arches->item[0], repo, pkg, buf, len, 0);
}

int apk_cache_download(struct apk_database *db, struct apk_repository *repo,
		       struct apk_package *pkg, int autoupdate,
		       apk_progress_cb cb, void *cb_ctx)
{
	struct apk_out *out = &db->ctx->out;
	struct stat st = {0};
	struct apk_url_print urlp;
	struct apk_istream *is;
	struct apk_ostream *os;
	struct apk_extract_ctx ectx;
	char url[PATH_MAX];
	char cacheitem[128];
	int r;
	time_t now = time(NULL);

	if (db->cache_fd < 0) return db->cache_fd;

	if (pkg != NULL)
		r = apk_pkg_format_cache_pkg(APK_BLOB_BUF(cacheitem), pkg);
	else
		r = apk_repo_format_cache_index(APK_BLOB_BUF(cacheitem), repo);
	if (r < 0) return r;

	r = apk_repo_format_real_url(db->arches->item[0], repo, pkg, url, sizeof(url), &urlp);
	if (r < 0) return r;

	if (autoupdate && !(db->ctx->force & APK_FORCE_REFRESH)) {
		if (fstatat(db->cache_fd, cacheitem, &st, 0) == 0 &&
		    now - st.st_mtime <= db->ctx->cache_max_age)
			return -EALREADY;
	}
	apk_notice(out, "fetch " URL_FMT, URL_PRINTF(urlp));

	if (db->ctx->flags & APK_SIMULATE) return 0;

	os = apk_ostream_to_file(db->cache_fd, cacheitem, 0644);
	if (IS_ERR(os)) return PTR_ERR(os);

	if (cb) cb(cb_ctx, 0);

	is = apk_istream_from_url(url, apk_db_url_since(db, st.st_mtime));
	is = apk_istream_tee(is, os, autoupdate ? 0 : APK_ISTREAM_TEE_COPY_META, cb, cb_ctx);
	apk_extract_init(&ectx, db->ctx, NULL);
	if (pkg) apk_extract_verify_identity(&ectx, pkg->digest_alg, apk_pkg_digest_blob(pkg));
	r = apk_extract(&ectx, is);
	if (r == -EALREADY) {
		if (autoupdate) utimensat(db->cache_fd, cacheitem, NULL, 0);
		return r;
	}
	return r;
}

static struct apk_db_dir_instance *find_diri(struct apk_installed_package *ipkg,
					     apk_blob_t dirname,
					     struct apk_db_dir_instance *curdiri,
					     struct hlist_node ***tail)
{
	struct hlist_node *n;
	struct apk_db_dir_instance *diri;

	if (curdiri != NULL &&
	    apk_blob_compare(APK_BLOB_PTR_LEN(curdiri->dir->name,
					      curdiri->dir->namelen),
			     dirname) == 0)
		return curdiri;

	hlist_for_each_entry(diri, n, &ipkg->owned_dirs, pkg_dirs_list) {
		if (apk_blob_compare(APK_BLOB_PTR_LEN(diri->dir->name,
						      diri->dir->namelen), dirname) == 0) {
			if (tail != NULL)
				*tail = hlist_tail_ptr(&diri->owned_files);
			return diri;
		}
	}
	return NULL;
}

int apk_db_read_overlay(struct apk_database *db, struct apk_istream *is)
{
	struct apk_db_dir_instance *diri = NULL;
	struct hlist_node **diri_node = NULL, **file_diri_node = NULL;
	struct apk_package *pkg = &db->overlay_tmpl.pkg;
	struct apk_installed_package *ipkg;
	apk_blob_t token = APK_BLOB_STR("\n"), line, bdir, bfile;

	if (IS_ERR(is)) return PTR_ERR(is);

	ipkg = apk_pkg_install(db, pkg);
	if (ipkg == NULL) {
		apk_istream_error(is, -ENOMEM);
		goto err;
	}

	diri_node = hlist_tail_ptr(&ipkg->owned_dirs);

	while (apk_istream_get_delim(is, token, &line) == 0) {
		if (!apk_blob_rsplit(line, '/', &bdir, &bfile)) {
			apk_istream_error(is, -APKE_V2PKG_FORMAT);
			break;
		}

		if (bfile.len == 0) {
			diri = apk_db_diri_new(db, pkg, bdir, &diri_node);
			file_diri_node = &diri->owned_files.first;
			diri->dir->created = 1;
		} else {
			diri = find_diri(ipkg, bdir, diri, &file_diri_node);
			if (diri == NULL) {
				diri = apk_db_diri_new(db, pkg, bdir, &diri_node);
				file_diri_node = &diri->owned_files.first;
			}
			(void) apk_db_file_get(db, diri, bfile, &file_diri_node);
		}
	}
err:
	return apk_istream_close(is);
}

static int apk_db_fdb_read(struct apk_database *db, struct apk_istream *is, int repo, unsigned layer)
{
	struct apk_out *out = &db->ctx->out;
	struct apk_package_tmpl tmpl;
	struct apk_installed_package *ipkg = NULL;
	struct apk_db_dir_instance *diri = NULL;
	struct apk_db_file *file = NULL;
	struct apk_db_acl *acl;
	struct hlist_node **diri_node = NULL;
	struct hlist_node **file_diri_node = NULL;
	struct apk_digest file_digest, xattr_digest;
	apk_blob_t token = APK_BLOB_STR("\n"), l;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	int field, r, lineno = 0;

	if (IS_ERR(is)) return PTR_ERR(is);

	apk_pkgtmpl_init(&tmpl);
	tmpl.pkg.layer = layer;

	while (apk_istream_get_delim(is, token, &l) == 0) {
		lineno++;

		if (l.len < 2) {
			if (!tmpl.pkg.name) continue;
			if (diri) apk_db_dir_apply_diri_permissions(db, diri);

			if (repo >= 0) {
				tmpl.pkg.repos |= BIT(repo);
			} else if (repo == -2) {
				tmpl.pkg.cached_non_repository = 1;
			} else if (repo == -1 && ipkg == NULL) {
				/* Installed package without files */
				ipkg = apk_pkg_install(db, &tmpl.pkg);
			}

			if (apk_db_pkg_add(db, &tmpl) == NULL)
				goto err_fmt;

			tmpl.pkg.layer = layer;
			ipkg = NULL;
			diri = NULL;
			file_diri_node = NULL;
			continue;
		}

		/* Get field */
		field = l.ptr[0];
		if (l.ptr[1] != ':') goto err_fmt;
		l.ptr += 2;
		l.len -= 2;

		/* Standard index line? */
		r = apk_pkgtmpl_add_info(db, &tmpl, field, l);
		if (r == 0) continue;
		if (r == 1 && repo == -1 && ipkg == NULL) {
			/* Instert to installed database; this needs to
			 * happen after package name has been read, but
			 * before first FDB entry. */
			ipkg = apk_pkg_install(db, &tmpl.pkg);
			diri_node = hlist_tail_ptr(&ipkg->owned_dirs);
		}
		if (repo != -1 || ipkg == NULL) continue;

		/* Check FDB special entries */
		switch (field) {
		case 'F':
			if (diri) apk_db_dir_apply_diri_permissions(db, diri);
			if (tmpl.pkg.name == NULL) goto bad_entry;
			diri = find_diri(ipkg, l, NULL, &diri_node);
			if (!diri) diri = apk_db_diri_new(db, &tmpl.pkg, l, &diri_node);
			file_diri_node = hlist_tail_ptr(&diri->owned_files);
			break;
		case 'a':
			if (file == NULL) goto bad_entry;
		case 'M':
			if (diri == NULL) goto bad_entry;
			uid = apk_blob_pull_uint(&l, 10);
			apk_blob_pull_char(&l, ':');
			gid = apk_blob_pull_uint(&l, 10);
			apk_blob_pull_char(&l, ':');
			mode = apk_blob_pull_uint(&l, 8);
			if (apk_blob_pull_blob_match(&l, APK_BLOB_STR(":")))
				apk_blob_pull_digest(&l, &xattr_digest);
			else
				apk_digest_reset(&xattr_digest);

			acl = apk_db_acl_atomize_digest(db, mode, uid, gid, &xattr_digest);
			if (field == 'M')
				diri->acl = acl;
			else
				file->acl = acl;
			break;
		case 'R':
			if (diri == NULL) goto bad_entry;
			file = apk_db_file_get(db, diri, l, &file_diri_node);
			break;
		case 'Z':
			if (file == NULL) goto bad_entry;
			apk_blob_pull_digest(&l, &file_digest);
			if (file_digest.alg == APK_DIGEST_SHA1 && ipkg->sha256_160)
				apk_digest_set(&file_digest, APK_DIGEST_SHA256_160);
			apk_dbf_digest_set(file, file_digest.alg, file_digest.data);
			break;
		case 'r':
			apk_blob_pull_deps(&l, db, &ipkg->replaces);
			break;
		case 'q':
			ipkg->replaces_priority = apk_blob_pull_uint(&l, 10);
			break;
		case 's':
			ipkg->repository_tag = apk_db_get_tag_id(db, l);
			break;
		case 'f':
			for (r = 0; r < l.len; r++) {
				switch (l.ptr[r]) {
				case 'f': ipkg->broken_files = 1; break;
				case 's': ipkg->broken_script = 1; break;
				case 'x': ipkg->broken_xattr = 1; break;
				case 'S': ipkg->sha256_160 = 1; break;
				default:
					if (!(db->ctx->force & APK_FORCE_OLD_APK))
						goto old_apk_tools;
				}
			}
			break;
		default:
			if (r != 0 && !(db->ctx->force & APK_FORCE_OLD_APK))
				goto old_apk_tools;
			/* Installed. So mark the package as installable. */
			tmpl.pkg.filename_ndx = 0;
			continue;
		}
		if (APK_BLOB_IS_NULL(l)) goto bad_entry;
	}
	apk_pkgtmpl_free(&tmpl);
	return apk_istream_close(is);
old_apk_tools:
	/* Installed db should not have unsupported fields */
	apk_err(out, "This apk-tools is too old to handle installed packages");
	goto err_fmt;
bad_entry:
	apk_err(out, "FDB format error (line %d, entry '%c')", lineno, field);
err_fmt:
	is->err = -APKE_V2DB_FORMAT;
	apk_pkgtmpl_free(&tmpl);
	return apk_istream_close(is);
}

int apk_db_index_read(struct apk_database *db, struct apk_istream *is, int repo)
{
	return apk_db_fdb_read(db, is, repo, 0);
}

static void apk_blob_push_db_acl(apk_blob_t *b, char field, struct apk_db_acl *acl)
{
	char hdr[2] = { field, ':' };

	apk_blob_push_blob(b, APK_BLOB_BUF(hdr));
	apk_blob_push_uint(b, acl->uid, 10);
	apk_blob_push_blob(b, APK_BLOB_STR(":"));
	apk_blob_push_uint(b, acl->gid, 10);
	apk_blob_push_blob(b, APK_BLOB_STR(":"));
	apk_blob_push_uint(b, acl->mode, 8);
	if (acl->xattr_hash_len != 0) {
		apk_blob_push_blob(b, APK_BLOB_STR(":"));
		apk_blob_push_hash(b, apk_acl_digest_blob(acl));
	}
	apk_blob_push_blob(b, APK_BLOB_STR("\n"));
}

static int apk_db_fdb_write(struct apk_database *db, struct apk_installed_package *ipkg, struct apk_ostream *os)
{
	struct apk_package *pkg = ipkg->pkg;
	struct apk_db_dir_instance *diri;
	struct apk_db_file *file;
	struct hlist_node *c1, *c2;
	char buf[1024+PATH_MAX];
	apk_blob_t bbuf = APK_BLOB_BUF(buf);
	int r = 0;

	if (IS_ERR(os)) return PTR_ERR(os);

	r = apk_pkg_write_index_header(pkg, os);
	if (r < 0) goto err;

	if (apk_array_len(ipkg->replaces) != 0) {
		apk_blob_push_blob(&bbuf, APK_BLOB_STR("r:"));
		apk_blob_push_deps(&bbuf, db, ipkg->replaces);
		apk_blob_push_blob(&bbuf, APK_BLOB_STR("\n"));
	}
	if (ipkg->replaces_priority) {
		apk_blob_push_blob(&bbuf, APK_BLOB_STR("q:"));
		apk_blob_push_uint(&bbuf, ipkg->replaces_priority, 10);
		apk_blob_push_blob(&bbuf, APK_BLOB_STR("\n"));
	}
	if (ipkg->repository_tag) {
		apk_blob_push_blob(&bbuf, APK_BLOB_STR("s:"));
		apk_blob_push_blob(&bbuf, db->repo_tags[ipkg->repository_tag].plain_name);
		apk_blob_push_blob(&bbuf, APK_BLOB_STR("\n"));
	}
	if (ipkg->broken_files || ipkg->broken_script || ipkg->broken_xattr || ipkg->sha256_160) {
		apk_blob_push_blob(&bbuf, APK_BLOB_STR("f:"));
		if (ipkg->broken_files)
			apk_blob_push_blob(&bbuf, APK_BLOB_STR("f"));
		if (ipkg->broken_script)
			apk_blob_push_blob(&bbuf, APK_BLOB_STR("s"));
		if (ipkg->broken_xattr)
			apk_blob_push_blob(&bbuf, APK_BLOB_STR("x"));
		if (ipkg->sha256_160)
			apk_blob_push_blob(&bbuf, APK_BLOB_STR("S"));
		apk_blob_push_blob(&bbuf, APK_BLOB_STR("\n"));
	}
	hlist_for_each_entry(diri, c1, &ipkg->owned_dirs, pkg_dirs_list) {
		apk_blob_push_blob(&bbuf, APK_BLOB_STR("F:"));
		apk_blob_push_blob(&bbuf, APK_BLOB_PTR_LEN(diri->dir->name, diri->dir->namelen));
		apk_blob_push_blob(&bbuf, APK_BLOB_STR("\n"));

		if (diri->acl != apk_default_acl_dir)
			apk_blob_push_db_acl(&bbuf, 'M', diri->acl);

		bbuf = apk_blob_pushed(APK_BLOB_BUF(buf), bbuf);
		if (APK_BLOB_IS_NULL(bbuf)) {
			r = -ENOBUFS;
			goto err;
		}
		r = apk_ostream_write(os, bbuf.ptr, bbuf.len);
		if (r < 0) goto err;
		bbuf = APK_BLOB_BUF(buf);

		hlist_for_each_entry(file, c2, &diri->owned_files, diri_files_list) {
			apk_blob_push_blob(&bbuf, APK_BLOB_STR("R:"));
			apk_blob_push_blob(&bbuf, APK_BLOB_PTR_LEN(file->name, file->namelen));
			apk_blob_push_blob(&bbuf, APK_BLOB_STR("\n"));

			if (file->acl != apk_default_acl_file)
				apk_blob_push_db_acl(&bbuf, 'a', file->acl);

			if (file->digest_alg != APK_DIGEST_NONE) {
				apk_blob_push_blob(&bbuf, APK_BLOB_STR("Z:"));
				apk_blob_push_hash(&bbuf, apk_dbf_digest_blob(file));
				apk_blob_push_blob(&bbuf, APK_BLOB_STR("\n"));
			}

			bbuf = apk_blob_pushed(APK_BLOB_BUF(buf), bbuf);
			if (APK_BLOB_IS_NULL(bbuf)) {
				r = -ENOBUFS;
				goto err;
			}
			r = apk_ostream_write(os, bbuf.ptr, bbuf.len);
			if (r < 0) goto err;
			bbuf = APK_BLOB_BUF(buf);
		}
	}
	r = apk_ostream_write(os, "\n", 1);
err:
	if (r < 0) apk_ostream_cancel(os, r);
	return r;
}

static int apk_db_scriptdb_write(struct apk_database *db, struct apk_installed_package *ipkg, struct apk_ostream *os)
{
	struct apk_package *pkg = ipkg->pkg;
	struct apk_file_info fi;
	char filename[256];
	apk_blob_t bfn;
	int r, i;

	if (IS_ERR(os)) return PTR_ERR(os);

	for (i = 0; i < APK_SCRIPT_MAX; i++) {
		if (!ipkg->script[i].ptr) continue;

		fi = (struct apk_file_info) {
			.name = filename,
			.size = ipkg->script[i].len,
			.mode = 0755 | S_IFREG,
			.mtime = pkg->build_time,
		};
		/* The scripts db expects file names in format:
		 * pkg-version.<hexdump of package checksum>.action */
		bfn = APK_BLOB_BUF(filename);
		apk_blob_push_blob(&bfn, APK_BLOB_STR(pkg->name->name));
		apk_blob_push_blob(&bfn, APK_BLOB_STR("-"));
		apk_blob_push_blob(&bfn, *pkg->version);
		apk_blob_push_blob(&bfn, APK_BLOB_STR("."));
		apk_blob_push_hash_hex(&bfn, apk_pkg_hash_blob(pkg));
		apk_blob_push_blob(&bfn, APK_BLOB_STR("."));
		apk_blob_push_blob(&bfn, APK_BLOB_STR(apk_script_types[i]));
		apk_blob_push_blob(&bfn, APK_BLOB_PTR_LEN("", 1));

		r = apk_tar_write_entry(os, &fi, ipkg->script[i].ptr);
		if (r < 0) {
			apk_ostream_cancel(os, -APKE_V2DB_FORMAT);
			break;
		}
	}

	return r;
}

static int apk_read_script_archive_entry(void *ctx,
					 const struct apk_file_info *ae,
					 struct apk_istream *is)
{
	struct apk_database *db = (struct apk_database *) ctx;
	struct apk_package *pkg;
	char *fncsum, *fnaction;
	struct apk_digest digest;
	apk_blob_t blob;
	int type;

	if (!S_ISREG(ae->mode))
		return 0;

	/* The scripts db expects file names in format:
	 * pkgname-version.<hexdump of package checksum>.action */
	fnaction = memrchr(ae->name, '.', strlen(ae->name));
	if (fnaction == NULL || fnaction == ae->name)
		return 0;
	fncsum = memrchr(ae->name, '.', fnaction - ae->name - 1);
	if (fncsum == NULL)
		return 0;
	fnaction++;
	fncsum++;

	/* Parse it */
	type = apk_script_type(fnaction);
	if (type == APK_SCRIPT_INVALID)
		return 0;
	blob = APK_BLOB_PTR_PTR(fncsum, fnaction - 2);
	apk_blob_pull_digest(&blob, &digest);

	/* Attach script */
	pkg = apk_db_get_pkg(db, &digest);
	if (pkg != NULL && pkg->ipkg != NULL)
		apk_ipkg_add_script(pkg->ipkg, is, type, ae->size);

	return 0;
}

static int apk_db_triggers_write(struct apk_database *db, struct apk_installed_package *ipkg, struct apk_ostream *os)
{
	char buf[APK_BLOB_DIGEST_BUF];
	apk_blob_t bfn;
	char **trigger;

	if (IS_ERR(os)) return PTR_ERR(os);
	if (apk_array_len(ipkg->triggers) == 0) return 0;

	bfn = APK_BLOB_BUF(buf);
	apk_blob_push_hash(&bfn, apk_pkg_hash_blob(ipkg->pkg));
	bfn = apk_blob_pushed(APK_BLOB_BUF(buf), bfn);
	apk_ostream_write(os, bfn.ptr, bfn.len);

	foreach_array_item(trigger, ipkg->triggers) {
		apk_ostream_write(os, " ", 1);
		apk_ostream_write_string(os, *trigger);
	}
	apk_ostream_write(os, "\n", 1);
	return 0;
}

static void apk_db_pkg_add_triggers(struct apk_database *db, struct apk_installed_package *ipkg, apk_blob_t triggers)
{
	apk_blob_foreach_word(word, triggers)
		apk_string_array_add(&ipkg->triggers, apk_blob_cstr(word));

	if (apk_array_len(ipkg->triggers) != 0 &&
	    !list_hashed(&ipkg->trigger_pkgs_list))
		list_add_tail(&ipkg->trigger_pkgs_list,
			      &db->installed.triggers);
}

static int apk_db_add_trigger(struct apk_database *db, apk_blob_t l)
{
	struct apk_digest digest;
	struct apk_package *pkg;

	apk_blob_pull_digest(&l, &digest);
	apk_blob_pull_char(&l, ' ');
	pkg = apk_db_get_pkg(db, &digest);
	if (pkg && pkg->ipkg) apk_db_pkg_add_triggers(db, pkg->ipkg, l);
	return 0;
}

static int apk_db_read_layer(struct apk_database *db, unsigned layer)
{
	apk_blob_t blob, world;
	int r, fd, ret = 0, flags = db->ctx->open_flags;

	/* Read:
	 * 1. world
	 * 2. installed packages db
	 * 3. triggers db
	 * 4. scripts db
	 */

	fd = openat(db->root_fd, apk_db_layer_name(layer), O_RDONLY | O_CLOEXEC);
	if (fd < 0) return -errno;

	if (!(flags & APK_OPENF_NO_WORLD)) {
		if (layer == APK_DB_LAYER_ROOT)
			ret = apk_blob_from_file(db->root_fd, apk_world_file, &world);
		else
			ret = apk_blob_from_file(fd, "world", &world);

		if (!ret) {
			blob = apk_blob_trim(world);
			ret = apk_blob_pull_deps(&blob, db, &db->world);
			free(world.ptr);
		} else if (layer == APK_DB_LAYER_ROOT) {
			ret = -ENOENT;
		}
	}

	if (!(flags & APK_OPENF_NO_INSTALLED)) {
		r = apk_db_fdb_read(db, apk_istream_from_file(fd, "installed"), -1, layer);
		if (!ret && r != -ENOENT) ret = r;
		r = apk_db_parse_istream(db, apk_istream_from_file(fd, "triggers"), apk_db_add_trigger);
		if (!ret && r != -ENOENT) ret = r;
	}

	if (!(flags & APK_OPENF_NO_SCRIPTS)) {
		r = apk_tar_parse(apk_istream_from_file(fd, "scripts.tar"),
				  apk_read_script_archive_entry, db, db->id_cache);
		if (!ret && r != -ENOENT) ret = r;
	}

	close(fd);
	return ret;
}

static int apk_db_index_write_nr_cache(struct apk_database *db)
{
	struct apk_package_array *pkgs;
	struct apk_package **ppkg;
	struct apk_ostream *os;

	if (!apk_db_cache_active(db)) return 0;

	/* Write list of installed non-repository packages to
	 * cached index file */
	os = apk_ostream_to_file(db->cache_fd, "installed", 0644);
	if (IS_ERR(os)) return PTR_ERR(os);

	pkgs = apk_db_sorted_installed_packages(db);
	foreach_array_item(ppkg, pkgs) {
		struct apk_package *pkg = *ppkg;
		if ((pkg->repos == BIT(APK_REPOSITORY_CACHED) ||
		     (pkg->repos == 0 && !pkg->installed_size))) {
			if (apk_pkg_write_index_entry(pkg, os) < 0) break;
		}
	}
	return apk_ostream_close(os);
}

static int apk_db_add_protected_path(struct apk_database *db, apk_blob_t blob)
{
	int protect_mode = APK_PROTECT_NONE;

	/* skip empty lines and comments */
	if (blob.len == 0)
		return 0;

	switch (blob.ptr[0]) {
	case '#':
		return 0;
	case '-':
		protect_mode = APK_PROTECT_IGNORE;
		break;
	case '+':
		protect_mode = APK_PROTECT_CHANGED;
		break;
	case '@':
		protect_mode = APK_PROTECT_SYMLINKS_ONLY;
		break;
	case '!':
		protect_mode = APK_PROTECT_ALL;
		break;
	default:
		protect_mode = APK_PROTECT_CHANGED;
		goto no_mode_char;
	}
	blob.ptr++;
	blob.len--;

no_mode_char:
	/* skip leading and trailing path separators */
	while (blob.len && blob.ptr[0] == '/')
		blob.ptr++, blob.len--;
	while (blob.len && blob.ptr[blob.len-1] == '/')
		blob.len--;

	apk_protected_path_array_add(&db->protected_paths, (struct apk_protected_path) {
		.relative_pattern = apk_blob_cstr(blob),
		.protect_mode = protect_mode,
	});
	return 0;
}

static int file_ends_with_dot_list(const char *file)
{
	const char *ext = strrchr(file, '.');
	if (ext == NULL || strcmp(ext, ".list") != 0)
		return FALSE;
	return TRUE;
}

static int add_protected_paths_from_file(void *ctx, int dirfd, const char *file)
{
	struct apk_database *db = (struct apk_database *) ctx;

	if (!file_ends_with_dot_list(file)) return 0;
	apk_db_parse_istream(db, apk_istream_from_file(dirfd, file), apk_db_add_protected_path);
	return 0;
}

static void handle_alarm(int sig)
{
}

static void mark_in_cache(struct apk_database *db, int static_cache, int dirfd, const char *name, struct apk_package *pkg)
{
	if (pkg == NULL)
		return;

	pkg->repos |= BIT(APK_REPOSITORY_CACHED);
}

static int add_repos_from_file(void *ctx, int dirfd, const char *file)
{
	struct apk_database *db = (struct apk_database *) ctx;
	struct apk_out *out = &db->ctx->out;
	int r;

	if (dirfd != AT_FDCWD && dirfd != db->root_fd) {
		/* loading from repositories.d; check extension */
		if (!file_ends_with_dot_list(file))
			return 0;
	}

	r = apk_db_parse_istream(db, apk_istream_from_file(dirfd, file), apk_db_add_repository);
	if (r != 0) {
		if (dirfd != AT_FDCWD) return 0;
		apk_err(out, "failed to read repositories: %s: %s", file, apk_error_str(r));
		return r;
	}
	return 0;
}

static void apk_db_setup_repositories(struct apk_database *db, const char *cache_dir)
{
	/* This is the SHA-1 of the string 'cache'. Repo hashes like this
	 * are truncated to APK_CACHE_CSUM_BYTES and always use SHA-1. */
	db->repos[APK_REPOSITORY_CACHED] = (struct apk_repository) {
		.url = cache_dir,
		.hash.data = {
			0xb0,0x35,0x92,0x80,0x6e,0xfa,0xbf,0xee,0xb7,0x09,
			0xf5,0xa7,0x0a,0x7c,0x17,0x26,0x69,0xb0,0x05,0x38 },
		.hash.len = APK_DIGEST_LENGTH_SHA1,
		.hash.alg = APK_DIGEST_SHA1,
	};

	db->num_repos = APK_REPOSITORY_FIRST_CONFIGURED;
	db->local_repos |= BIT(APK_REPOSITORY_CACHED);
	db->available_repos |= BIT(APK_REPOSITORY_CACHED);

	db->num_repo_tags = 1;
}

static int apk_db_name_rdepends(apk_hash_item item, void *pctx)
{
	struct apk_name *name = item, *rname;
	struct apk_provider *p;
	struct apk_dependency *dep;
	struct apk_name *touched[128];
	unsigned num_touched = 0;

	foreach_array_item(p, name->providers) {
		foreach_array_item(dep, p->pkg->depends) {
			rname = dep->name;
			rname->is_dependency |= !apk_dep_conflict(dep);
			if (!(rname->state_int & 1)) {
				if (!rname->state_int) {
					if (num_touched < ARRAY_SIZE(touched))
						touched[num_touched] = rname;
					num_touched++;
				}
				rname->state_int |= 1;
				apk_name_array_add(&rname->rdepends, name);
			}
		}
		foreach_array_item(dep, p->pkg->install_if) {
			rname = dep->name;
			if (!(rname->state_int & 2)) {
				if (!rname->state_int) {
					if (num_touched < ARRAY_SIZE(touched))
						touched[num_touched] = rname;
					num_touched++;
				}
				rname->state_int |= 2;
				apk_name_array_add(&rname->rinstall_if, name);
			}
		}
	}

	if (num_touched > ARRAY_SIZE(touched)) {
		foreach_array_item(p, name->providers) {
			foreach_array_item(dep, p->pkg->depends)
				dep->name->state_int = 0;
			foreach_array_item(dep, p->pkg->install_if)
				dep->name->state_int = 0;
		}
	} else for (unsigned i = 0; i < num_touched; i++)
		touched[i]->state_int = 0;

	return 0;
}

#ifdef __linux__
static int detect_tmpfs_root(struct apk_database *db)
{
	struct statfs stfs;

	return fstatfs(db->root_fd, &stfs) == 0 && stfs.f_type == TMPFS_MAGIC;
}

static unsigned long map_statfs_flags(unsigned long f_flag)
{
	unsigned long mnt_flags = 0;
	if (f_flag & ST_RDONLY) mnt_flags |= MS_RDONLY;
	if (f_flag & ST_NOSUID) mnt_flags |= MS_NOSUID;
	if (f_flag & ST_NODEV)  mnt_flags |= MS_NODEV;
	if (f_flag & ST_NOEXEC) mnt_flags |= MS_NOEXEC;
	if (f_flag & ST_NOATIME) mnt_flags |= MS_NOATIME;
	if (f_flag & ST_NODIRATIME)mnt_flags |= MS_NODIRATIME;
#ifdef ST_RELATIME
	if (f_flag & ST_RELATIME) mnt_flags |= MS_RELATIME;
#endif
	if (f_flag & ST_SYNCHRONOUS) mnt_flags |= MS_SYNCHRONOUS;
	if (f_flag & ST_MANDLOCK) mnt_flags |= ST_MANDLOCK;
	return mnt_flags;
}

static char *find_mountpoint(int atfd, const char *rel_path)
{
	struct mntent *me;
	struct stat st;
	FILE *f;
	char *ret = NULL;
	dev_t dev;

	if (fstatat(atfd, rel_path, &st, 0) != 0)
		return NULL;
	dev = st.st_dev;

	f = setmntent("/proc/mounts", "r");
	if (f == NULL)
		return NULL;
	while ((me = getmntent(f)) != NULL) {
		if (strcmp(me->mnt_fsname, "rootfs") == 0)
			continue;
		if (fstatat(atfd, me->mnt_dir, &st, 0) == 0 &&
		    st.st_dev == dev) {
			ret = strdup(me->mnt_dir);
			break;
		}
	}
	endmntent(f);

	return ret;
}

static int remount_cache_rw(struct apk_database *db)
{
	struct apk_ctx *ac = db->ctx;
	struct apk_out *out = &ac->out;
	struct statfs stfs;

	if (fstatfs(db->cache_fd, &stfs) != 0) return -errno;

	db->cache_remount_flags = map_statfs_flags(stfs.f_flags);
	if ((ac->open_flags & (APK_OPENF_WRITE | APK_OPENF_CACHE_WRITE)) == 0) return 0;
	if ((db->cache_remount_flags & MS_RDONLY) == 0) return 0;

	/* remount cache read/write */
	db->cache_remount_dir = find_mountpoint(db->root_fd, db->cache_dir);
	if (db->cache_remount_dir == NULL) {
		apk_warn(out, "Unable to find cache directory mount point");
		return 0;
	}
	if (mount(0, db->cache_remount_dir, 0, MS_REMOUNT | (db->cache_remount_flags & ~MS_RDONLY), 0) != 0) {
		free(db->cache_remount_dir);
		db->cache_remount_dir = NULL;
		return -EROFS;
	}
	return 0;
}

static void remount_cache_ro(struct apk_database *db)
{
	if (!db->cache_remount_dir) return;
	mount(0, db->cache_remount_dir, 0, MS_REMOUNT | db->cache_remount_flags, 0);
	free(db->cache_remount_dir);
	db->cache_remount_dir = NULL;
}

static int mount_proc(struct apk_database *db)
{
	struct statfs stfs;

	/* mount /proc */
	if (asprintf(&db->root_proc_dir, "%s/proc", db->ctx->root) == -1)
		return -1;
	if (statfs(db->root_proc_dir, &stfs) != 0) {
		if (errno == ENOENT) mkdir(db->root_proc_dir, 0555);
		stfs.f_type = 0;
	}
	if (stfs.f_type != PROC_SUPER_MAGIC) {
		mount("proc", db->root_proc_dir, "proc", 0, 0);
	} else {
		/* was already mounted. prevent umount on close */
		free(db->root_proc_dir);
		db->root_proc_dir = NULL;
	}

	return 0;
}

static void unmount_proc(struct apk_database *db)
{
	if (db->root_proc_dir) {
		umount2(db->root_proc_dir, MNT_DETACH|UMOUNT_NOFOLLOW);
		free(db->root_proc_dir);
		db->root_proc_dir = NULL;
	}
}
#else
static int detect_tmpfs_root(struct apk_database *db)
{
	(void) db;
	return 0;
}

static int remount_cache_rw(struct apk_database *db)
{
	return 0;
}

static void remount_cache_ro(struct apk_database *db)
{
	(void) db;
}

static int mount_proc(struct apk_database *db)
{
	(void) db;
	return 0;
}

static void unmount_proc(struct apk_database *db)
{
	(void) db;
}
#endif

static int setup_cache(struct apk_database *db)
{
	db->cache_dir = db->ctx->cache_dir;
	db->cache_fd = openat(db->root_fd, db->cache_dir, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (db->cache_fd >= 0) return remount_cache_rw(db);
	if (db->ctx->cache_dir_set || errno != ENOENT) return -errno;

	// The default cache does not exists, fallback to static cache directory
	db->cache_dir = apk_static_cache_dir;
	db->cache_fd = openat(db->root_fd, db->cache_dir, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (db->cache_fd < 0) {
		apk_make_dirs(db->root_fd, db->cache_dir, 0755, 0755);
		db->cache_fd = openat(db->root_fd, db->cache_dir, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
		if (db->cache_fd < 0) {
			if (db->ctx->open_flags & APK_OPENF_WRITE) return -EROFS;
			db->cache_fd = -APKE_CACHE_NOT_AVAILABLE;
		}
	}
	return 0;
}

const char *apk_db_layer_name(int layer)
{
	switch (layer) {
	case APK_DB_LAYER_ROOT: return "lib/apk/db";
	case APK_DB_LAYER_UVOL: return "lib/apk/db-uvol";
	default:
		assert(!"invalid layer");
		return 0;
	}
}

#ifdef APK_UVOL_DB_TARGET
static void setup_uvol_target(struct apk_database *db)
{
	const struct apk_ctx *ac = db->ctx;
	const char *uvol_db = apk_db_layer_name(APK_DB_LAYER_UVOL);
	const char *uvol_target = APK_UVOL_DB_TARGET;
	const char *uvol_symlink_target = "../../" APK_UVOL_DB_TARGET;

	if (!(ac->open_flags & (APK_OPENF_WRITE|APK_OPENF_CREATE))) return;
	if (IS_ERR(ac->uvol)) return;
	if (faccessat(db->root_fd, uvol_db, F_OK, 0) == 0) return;
	if (faccessat(db->root_fd, uvol_target, F_OK, 0) != 0) return;

	// Create symlink from uvol_db to uvol_target in relative form
	symlinkat(uvol_symlink_target, db->root_fd, uvol_db);
}
#else
static void setup_uvol_target(struct apk_database *db) { }
#endif

void apk_db_init(struct apk_database *db)
{
	memset(db, 0, sizeof(*db));
	apk_balloc_init(&db->ba_names, (sizeof(struct apk_name) + 16) * 256);
	apk_balloc_init(&db->ba_pkgs, sizeof(struct apk_package) * 256);
	apk_balloc_init(&db->ba_deps, sizeof(struct apk_dependency) * 256);
	apk_balloc_init(&db->ba_files, (sizeof(struct apk_db_file) + 32) * 256);
	apk_hash_init(&db->available.names, &pkg_name_hash_ops, 20000);
	apk_hash_init(&db->available.packages, &pkg_info_hash_ops, 10000);
	apk_hash_init(&db->installed.dirs, &dir_hash_ops, 20000);
	apk_hash_init(&db->installed.files, &file_hash_ops, 200000);
	apk_atom_init(&db->atoms);
	apk_dependency_array_init(&db->world);
	apk_pkgtmpl_init(&db->overlay_tmpl);
	list_init(&db->installed.packages);
	list_init(&db->installed.triggers);
	apk_protected_path_array_init(&db->protected_paths);
	apk_string_array_init(&db->filename_array);
	apk_blobptr_array_init(&db->arches);
	apk_name_array_init(&db->available.sorted_names);
	apk_package_array_init(&db->installed.sorted_packages);
	db->permanent = 1;
	db->root_fd = -1;
	db->noarch = apk_atomize(&db->atoms, APK_BLOB_STRLIT("noarch"));
}

int apk_db_open(struct apk_database *db, struct apk_ctx *ac)
{
	struct apk_out *out = &ac->out;
	const char *msg = NULL;
	int r = -1, i;

	apk_default_acl_dir = apk_db_acl_atomize(db, 0755, 0, 0);
	apk_default_acl_file = apk_db_acl_atomize(db, 0644, 0, 0);

	db->ctx = ac;
	if (ac->open_flags == 0) {
		msg = "Invalid open flags (internal error)";
		goto ret_r;
	}
	if ((ac->open_flags & APK_OPENF_WRITE) &&
	    !(ac->open_flags & APK_OPENF_NO_AUTOUPDATE) &&
	    !(ac->flags & APK_NO_NETWORK))
		db->autoupdate = 1;

	apk_db_setup_repositories(db, ac->cache_dir);
	db->root_fd = apk_ctx_fd_root(ac);
	db->cache_fd = -APKE_CACHE_NOT_AVAILABLE;
	db->permanent = !detect_tmpfs_root(db);
	db->usermode = !!(ac->open_flags & APK_OPENF_USERMODE);

	if (!(ac->open_flags & APK_OPENF_CREATE)) {
		// Autodetect usermode from the installeddb owner
		struct stat st;
		if (fstatat(db->root_fd, apk_db_layer_name(APK_DB_LAYER_ROOT), &st, 0) == 0 &&
		    st.st_uid != 0)
			db->usermode = 1;
	}
	if (db->usermode) db->extract_flags |= APK_FSEXTRACTF_NO_CHOWN | APK_FSEXTRACTF_NO_SYS_XATTRS | APK_FSEXTRACTF_NO_DEVICES;

	setup_uvol_target(db);

	if (apk_array_len(ac->arch_list) && (ac->root_set || (ac->open_flags & APK_OPENF_ALLOW_ARCH))) {
		char **arch;
		foreach_array_item(arch, ac->arch_list)
			apk_db_add_arch(db, APK_BLOB_STR(*arch));
		db->write_arch = ac->root_set;
	} else {
		struct apk_istream *is = apk_istream_from_file(db->root_fd, apk_arch_file);
		if (!IS_ERR(is)) apk_db_parse_istream(db, is, apk_db_add_arch);
	}
	if (apk_array_len(db->arches) == 0) {
		apk_db_add_arch(db, APK_BLOB_STR(APK_DEFAULT_ARCH));
		db->write_arch = 1;
	}

	if (ac->flags & APK_NO_CHROOT) db->root_dev_works = access("/dev/fd/0", R_OK) == 0;
	else db->root_dev_works = faccessat(db->root_fd, "dev/fd/0", R_OK, 0) == 0;

	db->id_cache = apk_ctx_get_id_cache(ac);

	if (ac->open_flags & APK_OPENF_WRITE) {
		msg = "Unable to lock database";
		db->lock_fd = openat(db->root_fd, apk_lock_file,
				     O_RDWR | O_CLOEXEC, 0600);
		// Check if old lock file exists
		if (db->lock_fd < 0 && errno == ENOENT) {
			db->lock_fd = openat(db->root_fd, apk_legacy_lock_file,
					     O_RDWR | O_CLOEXEC, 0600);
		}
		// If it still doesn't exist, try to create and use
		// the new lock file
		if (db->lock_fd < 0 && errno == ENOENT) {
			apk_make_dirs(db->root_fd, "run/apk", 0755, 0755);
			db->lock_fd = openat(db->root_fd, apk_lock_file,
					     O_CREAT | O_RDWR | O_CLOEXEC, 0600);
		}
		if (db->lock_fd < 0) goto ret_errno;

		if (flock(db->lock_fd, LOCK_EX | LOCK_NB) < 0) {
			struct sigaction sa, old_sa;

			if (!ac->lock_wait) goto ret_errno;

			apk_notice(out, "Waiting for repository lock");
			memset(&sa, 0, sizeof sa);
			sa.sa_handler = handle_alarm;
			sa.sa_flags   = SA_RESETHAND;
			sigaction(SIGALRM, &sa, &old_sa);

			alarm(ac->lock_wait);
			if (flock(db->lock_fd, LOCK_EX) < 0)
				goto ret_errno;

			alarm(0);
			sigaction(SIGALRM, &old_sa, NULL);
		}

		if (mount_proc(db) < 0)
			goto ret_errno;
	}

	if (ac->protected_paths) {
		apk_db_parse_istream(db, ac->protected_paths, apk_db_add_protected_path);
		ac->protected_paths = NULL;
	} else {
		apk_db_add_protected_path(db, APK_BLOB_STR("+etc"));
		apk_db_add_protected_path(db, APK_BLOB_STR("@etc/init.d"));
		apk_db_add_protected_path(db, APK_BLOB_STR("!etc/apk"));

		apk_dir_foreach_file(openat(db->root_fd, "etc/apk/protected_paths.d", O_DIRECTORY | O_RDONLY | O_CLOEXEC),
				     add_protected_paths_from_file, db);
	}

	/* figure out where to have the cache */
	if (!(db->ctx->flags & APK_NO_CACHE)) {
		if ((r = setup_cache(db)) < 0) {
			msg = "Unable to setup the cache";
			goto ret_r;
		}
	}

	if (db->ctx->flags & APK_OVERLAY_FROM_STDIN) {
		db->ctx->flags &= ~APK_OVERLAY_FROM_STDIN;
		apk_db_read_overlay(db, apk_istream_from_fd(STDIN_FILENO));
	}

	if ((db->ctx->open_flags & APK_OPENF_NO_STATE) != APK_OPENF_NO_STATE) {
		for (i = 0; i < APK_DB_LAYER_NUM; i++) {
			r = apk_db_read_layer(db, i);
			if (r) {
				if (i != APK_DB_LAYER_ROOT) continue;
				if (!(r == -ENOENT && (ac->open_flags & APK_OPENF_CREATE))) {
					msg = "Unable to read database";
					goto ret_r;
				}
			}
			db->active_layers |= BIT(i);
		}
	}

	if (!(ac->open_flags & APK_OPENF_NO_INSTALLED_REPO)) {
		if (apk_db_cache_active(db)) {
			apk_db_index_read(db, apk_istream_from_file(db->cache_fd, "installed"), -2);
		}
	}

	if (!(ac->open_flags & APK_OPENF_NO_CMDLINE_REPOS)) {
		char **repo;
		foreach_array_item(repo, ac->repository_list)
			apk_db_add_repository(db, APK_BLOB_STR(*repo));
	}

	if (!(ac->open_flags & APK_OPENF_NO_SYS_REPOS)) {
		if (ac->repositories_file == NULL) {
			add_repos_from_file(db, db->root_fd, "etc/apk/repositories");
			apk_dir_foreach_file(openat(db->root_fd, "etc/apk/repositories.d", O_DIRECTORY | O_RDONLY | O_CLOEXEC),
					     add_repos_from_file, db);
		} else {
			add_repos_from_file(db, AT_FDCWD, ac->repositories_file);
		}

		if (db->repositories.updated > 0)
			apk_db_index_write_nr_cache(db);
	}

	apk_hash_foreach(&db->available.names, apk_db_name_rdepends, db);

	if (apk_db_cache_active(db) && (ac->open_flags & (APK_OPENF_NO_REPOS|APK_OPENF_NO_INSTALLED)) == 0)
		apk_db_cache_foreach_item(db, mark_in_cache, 0);

	db->open_complete = 1;

	if (db->compat_newfeatures) {
		apk_warn(out,
			"This apk-tools is OLD! Some packages %s.",
			db->compat_notinstallable ? "are not installable" : "might not function properly");
	}
	if (db->compat_depversions) {
		apk_warn(out,
			"The indexes contain broken packages which %s.",
			db->compat_notinstallable ? "are not installable" : "might not function properly");
	}

	ac->db = db;
	return 0;

ret_errno:
	r = -errno;
ret_r:
	if (msg != NULL)
		apk_err(out, "%s: %s", msg, apk_error_str(-r));
	apk_db_close(db);

	return r;
}

struct write_ctx {
	struct apk_database *db;
	int fd;
};

static int apk_db_write_layers(struct apk_database *db)
{
	struct layer_data {
		int fd;
		struct apk_ostream *installed, *scripts, *triggers;
	} layers[APK_DB_LAYER_NUM] = {0};
	struct apk_ostream *os;
	struct apk_package **ppkg;
	struct apk_package_array *pkgs;
	int i, r, rr = 0;

	for (i = 0; i < APK_DB_LAYER_NUM; i++) {
		struct layer_data *ld = &layers[i];
		if (!(db->active_layers & BIT(i))) continue;

		ld->fd = openat(db->root_fd, apk_db_layer_name(i), O_DIRECTORY | O_RDONLY | O_CLOEXEC);
		if (ld->fd < 0) {
			if (i == 0) return -errno;
			continue;
		}
		ld->installed = apk_ostream_to_file(ld->fd, "installed", 0644);
		ld->scripts   = apk_ostream_to_file(ld->fd, "scripts.tar", 0644);
		ld->triggers  = apk_ostream_to_file(ld->fd, "triggers", 0644);

		if (i == 0)
			os = apk_ostream_to_file(db->root_fd, apk_world_file, 0644);
		else
			os = apk_ostream_to_file(ld->fd, "world", 0644);
		if (IS_ERR(os)) {
			if (!rr) rr = PTR_ERR(os);
			continue;
		}
		apk_deps_write_layer(db, db->world, os, APK_BLOB_PTR_LEN("\n", 1), i);
		apk_ostream_write(os, "\n", 1);
		r = apk_ostream_close(os);
		if (!rr) rr = r;
	}

	pkgs = apk_db_sorted_installed_packages(db);
	foreach_array_item(ppkg, pkgs) {
		struct apk_package *pkg = *ppkg;
		struct layer_data *ld = &layers[pkg->layer];
		if (!ld->fd) continue;
		apk_db_fdb_write(db, pkg->ipkg, ld->installed);
		apk_db_scriptdb_write(db, pkg->ipkg, ld->scripts);
		apk_db_triggers_write(db, pkg->ipkg, ld->triggers);
	}

	for (i = 0; i < APK_DB_LAYER_NUM; i++) {
		struct layer_data *ld = &layers[i];
		if (!(db->active_layers & BIT(i))) continue;

		if (!IS_ERR(ld->installed))
			r = apk_ostream_close(ld->installed);
		else	r = PTR_ERR(ld->installed);
		if (!rr) rr = r;

		if (!IS_ERR(ld->scripts)) {
			apk_tar_write_entry(ld->scripts, NULL, NULL);
			r = apk_ostream_close(ld->scripts);
		} else	r = PTR_ERR(ld->scripts);
		if (!rr) rr = r;

		if (!IS_ERR(ld->triggers))
			r = apk_ostream_close(ld->triggers);
		else	r = PTR_ERR(ld->triggers);
		if (!rr) rr = r;

		close(ld->fd);
	}
	return rr;
}

static int apk_db_write_arch(struct apk_database *db)
{
	struct apk_ostream *os;
	apk_blob_t **arch;

	os = apk_ostream_to_file(db->root_fd, apk_arch_file, 0644);
	if (IS_ERR(os)) return PTR_ERR(os);

	foreach_array_item(arch, db->arches) {
		apk_ostream_write(os, (*arch)->ptr, (*arch)->len);
		apk_ostream_write(os, "\n", 1);
	}
	return apk_ostream_close(os);
}

int apk_db_write_config(struct apk_database *db)
{
	struct apk_out *out = &db->ctx->out;
	int r, rr = 0;

	if ((db->ctx->flags & APK_SIMULATE) || db->ctx->root == NULL)
		return 0;

	if (db->ctx->open_flags & APK_OPENF_CREATE) {
		apk_make_dirs(db->root_fd, "lib/apk/db", 0755, 0755);
		apk_make_dirs(db->root_fd, "etc/apk", 0755, 0755);
	} else if (db->lock_fd == 0) {
		apk_err(out, "Refusing to write db without write lock!");
		return -1;
	}

	if (db->write_arch) {
		r = apk_db_write_arch(db);
		if (!rr) rr = r;
	}

	r = apk_db_write_layers(db);
	if (!rr) rr = r;

	r = apk_db_index_write_nr_cache(db);
	if (r < 0 && !rr) rr = r;

	if (rr) {
		apk_err(out, "System state may be inconsistent: failed to write database: %s",
			apk_error_str(rr));
	}
	return rr;
}

void apk_db_close(struct apk_database *db)
{
	struct apk_installed_package *ipkg, *ipkgn;
	struct apk_db_dir_instance *diri;
	struct apk_protected_path *ppath;
	struct hlist_node *dc, *dn;
	int i;

	/* Cleaning up the directory tree will cause mode, uid and gid
	 * of all modified (package providing that directory got removed)
	 * directories to be reset. */
	list_for_each_entry_safe(ipkg, ipkgn, &db->installed.packages, installed_pkgs_list) {
		hlist_for_each_entry_safe(diri, dc, dn, &ipkg->owned_dirs, pkg_dirs_list) {
			apk_db_diri_free(db, diri, APK_DIR_FREE);
		}
		apk_pkg_uninstall(NULL, ipkg->pkg);
	}

	for (i = APK_REPOSITORY_FIRST_CONFIGURED; i < db->num_repos; i++) {
		free((void*) db->repos[i].url);
		free(db->repos[i].description.ptr);
	}
	foreach_array_item(ppath, db->protected_paths)
		free(ppath->relative_pattern);
	apk_protected_path_array_free(&db->protected_paths);

	apk_blobptr_array_free(&db->arches);
	apk_string_array_free(&db->filename_array);
	apk_pkgtmpl_free(&db->overlay_tmpl);
	apk_dependency_array_free(&db->world);
	apk_name_array_free(&db->available.sorted_names);
	apk_package_array_free(&db->installed.sorted_packages);
	apk_hash_free(&db->available.packages);
	apk_hash_free(&db->available.names);
	apk_hash_free(&db->installed.files);
	apk_hash_free(&db->installed.dirs);
	apk_atom_free(&db->atoms);
	apk_balloc_destroy(&db->ba_names);
	apk_balloc_destroy(&db->ba_pkgs);
	apk_balloc_destroy(&db->ba_files);
	apk_balloc_destroy(&db->ba_deps);

	unmount_proc(db);
	remount_cache_ro(db);

	if (db->cache_fd > 0) close(db->cache_fd);
	if (db->lock_fd > 0) close(db->lock_fd);
}

int apk_db_get_tag_id(struct apk_database *db, apk_blob_t tag)
{
	int i;

	if (APK_BLOB_IS_NULL(tag))
		return APK_DEFAULT_REPOSITORY_TAG;

	if (tag.ptr[0] == '@') {
		for (i = 1; i < db->num_repo_tags; i++)
			if (apk_blob_compare(db->repo_tags[i].tag, tag) == 0)
				return i;
	} else {
		for (i = 1; i < db->num_repo_tags; i++)
			if (apk_blob_compare(db->repo_tags[i].plain_name, tag) == 0)
				return i;
	}
	if (i >= ARRAY_SIZE(db->repo_tags))
		return -1;

	db->num_repo_tags++;

	if (tag.ptr[0] == '@') {
		db->repo_tags[i].tag = *apk_atomize_dup(&db->atoms, tag);
	} else {
		char *tmp = alloca(tag.len + 1);
		tmp[0] = '@';
		memcpy(&tmp[1], tag.ptr, tag.len);
		db->repo_tags[i].tag = *apk_atomize_dup(&db->atoms, APK_BLOB_PTR_LEN(tmp, tag.len+1));
	}

	db->repo_tags[i].plain_name = db->repo_tags[i].tag;
	apk_blob_pull_char(&db->repo_tags[i].plain_name, '@');

	return i;
}

static int fire_triggers(apk_hash_item item, void *ctx)
{
	struct apk_database *db = (struct apk_database *) ctx;
	struct apk_db_dir *dbd = (struct apk_db_dir *) item;
	struct apk_installed_package *ipkg;
	char **triggerptr, *trigger;

	list_for_each_entry(ipkg, &db->installed.triggers, trigger_pkgs_list) {
		if (!ipkg->run_all_triggers && !dbd->modified) continue;
		foreach_array_item(triggerptr, ipkg->triggers) {
			trigger = *triggerptr;
			if (trigger[0] != '/') continue;
			if (fnmatch(trigger, dbd->rooted_name, FNM_PATHNAME) != 0) continue;

			/* And place holder for script name */
			if (apk_array_len(ipkg->pending_triggers) == 0) {
				apk_string_array_add(&ipkg->pending_triggers, NULL);
				db->pending_triggers++;
			}
			apk_string_array_add(&ipkg->pending_triggers, dbd->rooted_name);
			break;
		}
	}
	return 0;
}

int apk_db_fire_triggers(struct apk_database *db)
{
	apk_hash_foreach(&db->installed.dirs, fire_triggers, db);
	return db->pending_triggers;
}

int apk_db_run_script(struct apk_database *db, int fd, char **argv)
{
	char buf[APK_EXIT_STATUS_MAX_SIZE];
	struct apk_out *out = &db->ctx->out;
	int status;
	pid_t pid;
	static char * const clean_environment[] = {
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		NULL
	};

	pid = fork();
	if (pid == -1) {
		apk_err(out, "%s: fork: %s", apk_last_path_segment(argv[0]), strerror(errno));
		return -2;
	}
	if (pid == 0) {
		char *const *env = (db->ctx->flags & APK_PRESERVE_ENV) ? environ : clean_environment;

		umask(0022);
		if (fchdir(db->root_fd) != 0) {
			apk_err(out, "%s: fchdir: %s", apk_last_path_segment(argv[0]), strerror(errno));
			exit(127);
		}

		if (!(db->ctx->flags & APK_NO_CHROOT) && chroot(".") != 0) {
			apk_err(out, "%s: chroot: %s", apk_last_path_segment(argv[0]), strerror(errno));
			exit(127);
		}

		if (fd >= 0) fexecve(fd, argv, env);
		execve(argv[0], argv, env);

		apk_err(out, "%s: execve: %s", argv[0], strerror(errno));
		exit(127); /* should not get here */
	}
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR);

	if (apk_exit_status_str(status, buf, sizeof buf)) {
		apk_err(out, "%s: script %s", apk_last_path_segment(argv[0]), buf);
		return -1;
	}
	return 0;
}

int apk_db_cache_active(struct apk_database *db)
{
	return db->cache_fd > 0 && db->cache_dir != apk_static_cache_dir;
}

struct foreach_cache_item_ctx {
	struct apk_database *db;
	apk_cache_item_cb cb;
	int static_cache;
};

static int foreach_cache_file(void *pctx, int dirfd, const char *name)
{
	struct foreach_cache_item_ctx *ctx = (struct foreach_cache_item_ctx *) pctx;
	struct apk_database *db = ctx->db;
	struct apk_package *pkg = NULL;
	struct apk_provider *p0;
	apk_blob_t b = APK_BLOB_STR(name), bname, bver;

	if (apk_pkg_parse_name(b, &bname, &bver) == 0) {
		/* Package - search for it */
		struct apk_name *name = apk_db_get_name(db, bname);
		char tmp[PATH_MAX];
		if (name == NULL)
			goto no_pkg;

		foreach_array_item(p0, name->providers) {
			if (p0->pkg->name != name)
				continue;

			apk_pkg_format_cache_pkg(APK_BLOB_BUF(tmp), p0->pkg);
			if (apk_blob_compare(b, APK_BLOB_STR(tmp)) == 0) {
				pkg = p0->pkg;
				break;
			}
		}
	}
no_pkg:
	ctx->cb(db, ctx->static_cache, dirfd, name, pkg);

	return 0;
}

int apk_db_cache_foreach_item(struct apk_database *db, apk_cache_item_cb cb, int static_cache)
{
	struct foreach_cache_item_ctx ctx = { db, cb, static_cache };

	if (static_cache) {
		struct stat st1, st2;
		int fd = openat(db->root_fd, apk_static_cache_dir, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
		if (fd < 0) return fd;
		/* Do not handle static cache as static cache if the explicit
		 * cache is enabled at the static cache location */
		if (fstat(fd, &st1) == 0 && fstat(db->cache_fd, &st2) == 0 &&
		    st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino) {
			close(fd);
			return 0;
		}
		return apk_dir_foreach_file(fd, foreach_cache_file, &ctx);
	}
	if (db->cache_fd < 0) return db->cache_fd;
	return apk_dir_foreach_file(dup(db->cache_fd), foreach_cache_file, &ctx);
}

int apk_db_permanent(struct apk_database *db)
{
	return db->permanent;
}

int apk_db_check_world(struct apk_database *db, struct apk_dependency_array *world)
{
	struct apk_out *out = &db->ctx->out;
	struct apk_dependency *dep;
	int bad = 0, tag;

	if (db->ctx->force & APK_FORCE_BROKEN_WORLD)
		return 0;

	foreach_array_item(dep, world) {
		tag = dep->repository_tag;
		if (tag == 0 || db->repo_tags[tag].allowed_repos != 0)
			continue;
		if (tag < 0)
			tag = 0;
		apk_warn(out, "The repository tag for world dependency '%s" BLOB_FMT "' does not exist",
			dep->name->name, BLOB_PRINTF(db->repo_tags[tag].tag));
		bad++;
	}

	return bad;
}

struct apk_package *apk_db_get_pkg(struct apk_database *db,
				   struct apk_digest *id)
{
	if (id->len < APK_DIGEST_LENGTH_SHA1) return NULL;
	return apk_hash_get(&db->available.packages, APK_BLOB_PTR_LEN((char*)id->data, APK_DIGEST_LENGTH_SHA1));
}

struct apk_package *apk_db_get_file_owner(struct apk_database *db,
					  apk_blob_t filename)
{
	struct apk_db_file *dbf;
	struct apk_db_file_hash_key key;

	if (filename.len && filename.ptr[0] == '/')
		filename.len--, filename.ptr++;

	if (!apk_blob_rsplit(filename, '/', &key.dirname, &key.filename)) {
		key.dirname = APK_BLOB_NULL;
		key.filename = filename;
	}

	dbf = (struct apk_db_file *) apk_hash_get(&db->installed.files,
						  APK_BLOB_BUF(&key));
	if (dbf == NULL)
		return NULL;

	return dbf->diri->pkg;
}

unsigned int apk_db_get_pinning_mask_repos(struct apk_database *db, unsigned short pinning_mask)
{
	unsigned int repository_mask = 0;
	int i;

	for (i = 0; i < db->num_repo_tags && pinning_mask; i++) {
		if (!(BIT(i) & pinning_mask))
			continue;
		pinning_mask &= ~BIT(i);
		repository_mask |= db->repo_tags[i].allowed_repos;
	}
	return repository_mask;
}

struct apk_repository *apk_db_select_repo(struct apk_database *db,
					  struct apk_package *pkg)
{
	unsigned int repos;
	int i;

	/* Select repositories to use */
	repos = pkg->repos & db->available_repos;
	if (repos == 0)
		return NULL;

	if (repos & db->local_repos)
		repos &= db->local_repos;

	/* Pick first repository providing this package */
	for (i = APK_REPOSITORY_FIRST_CONFIGURED; i < APK_MAX_REPOS; i++) {
		if (repos & BIT(i))
			return &db->repos[i];
	}
	return &db->repos[APK_REPOSITORY_CACHED];
}

struct apkindex_ctx {
	struct apk_database *db;
	struct apk_extract_ctx ectx;
	int repo, found;
};

static int load_v2index(struct apk_extract_ctx *ectx, apk_blob_t *desc, struct apk_istream *is)
{
	struct apkindex_ctx *ctx = container_of(ectx, struct apkindex_ctx, ectx);
	struct apk_repository *repo = &ctx->db->repos[ctx->repo];

	repo->description = *desc;
	*desc = APK_BLOB_NULL;
	return apk_db_index_read(ctx->db, is, ctx->repo);
}

static int load_v3index(struct apk_extract_ctx *ectx, struct adb_obj *ndx)
{
	struct apkindex_ctx *ctx = container_of(ectx, struct apkindex_ctx, ectx);
	struct apk_database *db = ctx->db;
	struct apk_out *out = &db->ctx->out;
	struct apk_repository *repo = &db->repos[ctx->repo];
	struct apk_package_tmpl tmpl;
	struct adb_obj pkgs, pkginfo;
	int i, r = 0, num_broken = 0;

	apk_pkgtmpl_init(&tmpl);

	repo->description = apk_blob_dup(adb_ro_blob(ndx, ADBI_NDX_DESCRIPTION));
	adb_ro_obj(ndx, ADBI_NDX_PACKAGES, &pkgs);

	for (i = ADBI_FIRST; i <= adb_ra_num(&pkgs); i++) {
		adb_ro_obj(&pkgs, i, &pkginfo);
		apk_pkgtmpl_from_adb(db, &tmpl, &pkginfo);
		if (tmpl.id.alg == APK_DIGEST_NONE) {
			num_broken++;
			apk_pkgtmpl_reset(&tmpl);
			continue;
		}

		tmpl.pkg.repos |= BIT(ctx->repo);
		if (!apk_db_pkg_add(db, &tmpl)) {
			r = -APKE_ADB_SCHEMA;
			break;
		}
	}

	apk_pkgtmpl_free(&tmpl);
	if (num_broken) apk_warn(out, "Repository %s has %d packages without hash", repo->url, num_broken);
	return r;
}

static const struct apk_extract_ops extract_index = {
	.v2index = load_v2index,
	.v3index = load_v3index,
};

static int load_index(struct apk_database *db, struct apk_istream *is, int repo)
{
	struct apkindex_ctx ctx = {
		.db = db,
		.repo = repo,
	};
	if (IS_ERR(is)) return PTR_ERR(is);
	apk_extract_init(&ctx.ectx, db->ctx, &extract_index);
	return apk_extract(&ctx.ectx, is);
}

int apk_db_index_read_file(struct apk_database *db, const char *file, int repo)
{
	return load_index(db, apk_istream_from_file(AT_FDCWD, file), repo);
}

int apk_db_repository_check(struct apk_database *db)
{
	if (db->ctx->force & APK_FORCE_MISSING_REPOSITORIES) return 0;
	if (!db->repositories.stale && !db->repositories.unavailable) return 0;
	apk_err(&db->ctx->out,
		"Not continuing due to stale/unavailable repositories."
		"Use --force-missing-repositories to continue.");
	return -1;
}

int apk_db_add_repository(struct apk_database *db, apk_blob_t _repository)
{
	struct apk_out *out = &db->ctx->out;
	struct apk_repository *repo;
	struct apk_url_print urlp;
	apk_blob_t brepo, btag;
	int repo_num, r, tag_id = 0, atfd = AT_FDCWD, update_error = 0;
	char buf[PATH_MAX], *url;
	const char *error_action = "constructing url";

	brepo = _repository;
	btag = APK_BLOB_NULL;
	if (brepo.ptr == NULL || brepo.len == 0 || *brepo.ptr == '#')
		return 0;

	if (brepo.ptr[0] == '@') {
		apk_blob_cspn(brepo, APK_CTYPE_REPOSITORY_SEPARATOR, &btag, &brepo);
		apk_blob_spn(brepo, APK_CTYPE_REPOSITORY_SEPARATOR, NULL, &brepo);
		tag_id = apk_db_get_tag_id(db, btag);
	}

	url = apk_blob_cstr(brepo);
	for (repo_num = 0; repo_num < db->num_repos; repo_num++) {
		repo = &db->repos[repo_num];
		if (strcmp(url, repo->url) == 0) {
			db->repo_tags[tag_id].allowed_repos |=
				BIT(repo_num) & db->available_repos;
			free(url);
			return 0;
		}
	}
	if (db->num_repos >= APK_MAX_REPOS) {
		free(url);
		return -1;
	}

	repo_num = db->num_repos++;
	repo = &db->repos[repo_num];
	*repo = (struct apk_repository) {
		.url = url,
	};

	int is_remote = (apk_url_local_file(repo->url) == NULL);

	r = apk_repo_format_real_url(db->arches->item[0], repo, NULL, buf, sizeof(buf), &urlp);
	if (r != 0) goto err;

	error_action = "opening";
	apk_digest_calc(&repo->hash, APK_DIGEST_SHA256, buf, strlen(buf));

	if (!(db->ctx->flags & APK_NO_NETWORK))
		db->available_repos |= BIT(repo_num);

	if (is_remote) {
		if (db->ctx->flags & APK_NO_CACHE) {
			error_action = "fetching";
			apk_notice(out, "fetch " URL_FMT, URL_PRINTF(urlp));
		} else {
			error_action = "opening from cache";
			if (db->autoupdate) {
				update_error = apk_cache_download(db, repo, NULL, 1, NULL, NULL);
				switch (update_error) {
				case 0:
					db->repositories.updated++;
					break;
				case -EALREADY:
					update_error = 0;
					break;
				}
			}
			r = apk_repo_format_cache_index(APK_BLOB_BUF(buf), repo);
			if (r != 0) goto err;
			atfd = db->cache_fd;
		}
	} else if (strncmp(repo->url, "file://localhost/", 17) != 0) {
		db->local_repos |= BIT(repo_num);
		db->available_repos |= BIT(repo_num);
	}
	r = load_index(db, apk_istream_from_fd_url(atfd, buf, apk_db_url_since(db, 0)), repo_num);

err:
	if (r || update_error) {
		if (is_remote) {
			if (r) db->repositories.unavailable++;
			else db->repositories.stale++;
		}
		apk_url_parse(&urlp, repo->url);
		if (update_error)
			error_action = r ? "updating and opening" : "updating";
		else
			update_error = r;
		apk_warn(out, "%s " URL_FMT ": %s", error_action, URL_PRINTF(urlp),
			apk_error_str(update_error));
	}

	if (r != 0) {
		db->available_repos &= ~BIT(repo_num);
	} else {
		db->repo_tags[tag_id].allowed_repos |= BIT(repo_num);
	}

	return 0;
}

static void extract_cb(void *_ctx, size_t bytes_done)
{
	struct install_ctx *ctx = (struct install_ctx *) _ctx;
	if (!ctx->cb)
		return;
	ctx->cb(ctx->cb_ctx, min(ctx->installed_size + bytes_done, ctx->pkg->installed_size));
}

static void apk_db_run_pending_script(struct install_ctx *ctx)
{
	if (!ctx->script_pending) return;
	ctx->script_pending = FALSE;
	apk_ipkg_run_script(ctx->ipkg, ctx->db, ctx->script, ctx->script_args);
}

static int read_info_line(void *_ctx, apk_blob_t line)
{
	struct install_ctx *ctx = (struct install_ctx *) _ctx;
	struct apk_installed_package *ipkg = ctx->ipkg;
	struct apk_database *db = ctx->db;
	apk_blob_t l, r;

	if (line.ptr == NULL || line.len < 1 || line.ptr[0] == '#')
		return 0;

	if (!apk_blob_split(line, APK_BLOB_STR(" = "), &l, &r))
		return 0;

	if (apk_blob_compare(APK_BLOB_STR("replaces"), l) == 0) {
		apk_blob_pull_deps(&r, db, &ipkg->replaces);
	} else if (apk_blob_compare(APK_BLOB_STR("replaces_priority"), l) == 0) {
		ipkg->replaces_priority = apk_blob_pull_uint(&r, 10);
	} else if (apk_blob_compare(APK_BLOB_STR("triggers"), l) == 0) {
		apk_array_truncate(ipkg->triggers, 0);
		apk_db_pkg_add_triggers(db, ctx->ipkg, r);
	} else {
		apk_extract_v2_control(&ctx->ectx, l, r);
	}
	return 0;
}

static struct apk_db_dir_instance *apk_db_install_directory_entry(struct install_ctx * ctx, apk_blob_t dir)
{
	struct apk_database *db = ctx->db;
	struct apk_package *pkg = ctx->pkg;
	struct apk_installed_package *ipkg = pkg->ipkg;
	struct apk_db_dir_instance *diri;

	if (ctx->diri_node == NULL)
		ctx->diri_node = hlist_tail_ptr(&ipkg->owned_dirs);
	ctx->diri = diri = apk_db_diri_new(db, pkg, dir, &ctx->diri_node);
	ctx->file_diri_node = hlist_tail_ptr(&diri->owned_files);

	return diri;
}

static int contains_control_character(const char *str)
{
	for (const uint8_t *p = (const uint8_t *) str; *p; p++) {
		if (*p < 0x20 || *p == 0x7f) return 1;
	}
	return 0;
}

static int apk_db_install_v2meta(struct apk_extract_ctx *ectx, struct apk_istream *is)
{
	struct install_ctx *ctx = container_of(ectx, struct install_ctx, ectx);
	apk_blob_t l, token = APK_BLOB_STR("\n");
	int r;

	while (apk_istream_get_delim(is, token, &l) == 0) {
		r = read_info_line(ctx, l);
		if (r < 0) return r;
	}

	return 0;
}

static int apk_db_install_v3meta(struct apk_extract_ctx *ectx, struct adb_obj *pkg)
{
	static const int script_type_to_field[] = {
		[APK_SCRIPT_PRE_INSTALL]	= ADBI_SCRPT_PREINST,
		[APK_SCRIPT_POST_INSTALL]	= ADBI_SCRPT_POSTINST,
		[APK_SCRIPT_PRE_DEINSTALL]	= ADBI_SCRPT_PREDEINST,
		[APK_SCRIPT_POST_DEINSTALL]	= ADBI_SCRPT_POSTDEINST,
		[APK_SCRIPT_PRE_UPGRADE]	= ADBI_SCRPT_PREUPGRADE,
		[APK_SCRIPT_POST_UPGRADE]	= ADBI_SCRPT_POSTUPGRADE,
		[APK_SCRIPT_TRIGGER]		= ADBI_SCRPT_TRIGGER,
	};
	struct install_ctx *ctx = container_of(ectx, struct install_ctx, ectx);
	struct apk_database *db = ctx->db;
	struct apk_installed_package *ipkg = ctx->ipkg;
	struct adb_obj scripts, triggers, pkginfo, obj;
	int i;

	// Extract the information not available in index
	adb_ro_obj(pkg, ADBI_PKG_PKGINFO, &pkginfo);
	apk_deps_from_adb(&ipkg->replaces, db, adb_ro_obj(&pkginfo, ADBI_PI_REPLACES, &obj));
	ipkg->replaces_priority = adb_ro_int(pkg, ADBI_PKG_REPLACES_PRIORITY);
	ipkg->sha256_160 = 1;

	adb_ro_obj(pkg, ADBI_PKG_SCRIPTS, &scripts);
	for (i = 0; i < ARRAY_SIZE(script_type_to_field); i++) {
		apk_blob_t b = adb_ro_blob(&scripts, script_type_to_field[i]);
		if (APK_BLOB_IS_NULL(b)) continue;
		apk_ipkg_assign_script(ipkg, i, apk_blob_dup(b));
		ctx->script_pending |= (i == ctx->script);
	}

	adb_ro_obj(pkg, ADBI_PKG_TRIGGERS, &triggers);
	apk_string_array_resize(&ipkg->triggers, 0, adb_ra_num(&triggers));
	for (i = ADBI_FIRST; i <= adb_ra_num(&triggers); i++)
		apk_string_array_add(&ipkg->triggers, apk_blob_cstr(adb_ro_blob(&triggers, i)));
	if (apk_array_len(ctx->ipkg->triggers) != 0 && !list_hashed(&ipkg->trigger_pkgs_list))
		list_add_tail(&ipkg->trigger_pkgs_list, &db->installed.triggers);

	return 0;
}

static int apk_db_install_script(struct apk_extract_ctx *ectx, unsigned int type, size_t size, struct apk_istream *is)
{
	struct install_ctx *ctx = container_of(ectx, struct install_ctx, ectx);
	struct apk_package *pkg = ctx->pkg;

	apk_ipkg_add_script(pkg->ipkg, is, type, size);
	ctx->script_pending |= (type == ctx->script);
	return 0;
}

static int apk_db_install_file(struct apk_extract_ctx *ectx, const struct apk_file_info *ae, struct apk_istream *is)
{
	struct install_ctx *ctx = container_of(ectx, struct install_ctx, ectx);
	static const char dot1[] = "/./", dot2[] = "/../";
	struct apk_database *db = ctx->db;
	struct apk_ctx *ac = db->ctx;
	struct apk_out *out = &ac->out;
	struct apk_package *pkg = ctx->pkg, *opkg;
	struct apk_installed_package *ipkg = pkg->ipkg;
	apk_blob_t name = APK_BLOB_STR(ae->name), bdir, bfile;
	struct apk_db_dir_instance *diri = ctx->diri;
	struct apk_db_file *file, *link_target_file = NULL;
	int ret = 0, r;

	apk_db_run_pending_script(ctx);

	/* Sanity check the file name */
	if (ae->name[0] == '/' || contains_control_character(ae->name) ||
	    strncmp(ae->name, &dot1[1], 2) == 0 ||
	    strncmp(ae->name, &dot2[1], 3) == 0 ||
	    strstr(ae->name, dot1) || strstr(ae->name, dot2)) {
		apk_warn(out, PKG_VER_FMT": ignoring malicious file %s",
			PKG_VER_PRINTF(pkg), ae->name);
		ipkg->broken_files = 1;
		return 0;
	}

	/* Installable entry */
	if (!S_ISDIR(ae->mode)) {
		if (!apk_blob_rsplit(name, '/', &bdir, &bfile)) {
			bdir = APK_BLOB_NULL;
			bfile = name;
		}

		/* Make sure the file is part of the cached directory tree */
		diri = ctx->diri = find_diri(ipkg, bdir, diri, &ctx->file_diri_node);
		if (diri == NULL) {
			if (!APK_BLOB_IS_NULL(bdir)) {
				apk_err(out, PKG_VER_FMT": "BLOB_FMT": no dirent in archive",
					PKG_VER_PRINTF(pkg), BLOB_PRINTF(name));
				ipkg->broken_files = 1;
				return 0;
			}
			diri = apk_db_install_directory_entry(ctx, bdir);
		}

		/* Check hard link target to exist in this package */
		if (S_ISREG(ae->mode) && ae->link_target) {
			do {
				struct apk_db_file *lfile;
				struct apk_db_dir_instance *ldiri;
				struct hlist_node *n;
				apk_blob_t hldir, hlfile, hltarget = APK_BLOB_STR(ae->link_target);

				if (!apk_blob_rsplit(hltarget, '/', &hldir, &hlfile)) {
					hldir = APK_BLOB_NULL;
					hlfile = hltarget;
				}

				ldiri = find_diri(ipkg, hldir, diri, NULL);
				if (ldiri == NULL)
					break;

				hlist_for_each_entry(lfile, n, &ldiri->owned_files,
						     diri_files_list) {
					if (apk_blob_compare(APK_BLOB_PTR_LEN(lfile->name, lfile->namelen),
							     hlfile) == 0) {
						link_target_file = lfile;
						break;
					}
				}
			} while (0);

			if (!link_target_file) {
				apk_err(out, PKG_VER_FMT": "BLOB_FMT": no hard link target (%s) in archive",
					PKG_VER_PRINTF(pkg), BLOB_PRINTF(name), ae->link_target);
				ipkg->broken_files = 1;
				return 0;
			}
		}

		opkg = NULL;
		file = apk_db_file_query(db, bdir, bfile);
		if (file != NULL) {
			opkg = file->diri->pkg;
			switch (apk_pkg_replaces_file(opkg, pkg)) {
			case APK_PKG_REPLACES_CONFLICT:
				if (db->ctx->force & APK_FORCE_OVERWRITE) {
					apk_warn(out, PKG_VER_FMT": overwriting %s owned by "PKG_VER_FMT".",
						PKG_VER_PRINTF(pkg), ae->name, PKG_VER_PRINTF(opkg));
					break;
				}
				apk_err(out, PKG_VER_FMT": trying to overwrite %s owned by "PKG_VER_FMT".",
					PKG_VER_PRINTF(pkg), ae->name, PKG_VER_PRINTF(opkg));
				ipkg->broken_files = 1;
			case APK_PKG_REPLACES_NO:
				return 0;
			case APK_PKG_REPLACES_YES:
				break;
			}
		}

		if (opkg != pkg) {
			/* Create the file entry without adding it to hash */
			file = apk_db_file_new(db, diri, bfile, &ctx->file_diri_node);
		}

		apk_dbg2(out, "%s", ae->name);

		file->acl = apk_db_acl_atomize_digest(db, ae->mode, ae->uid, ae->gid, &ae->xattr_digest);
		r = apk_fs_extract(ac, ae, is, extract_cb, ctx, db->extract_flags, apk_pkg_ctx(pkg));
		if (r > 0) {
			char buf[APK_EXTRACTW_BUFSZ];
			if (r & APK_EXTRACTW_XATTR) ipkg->broken_xattr = 1;
			else ipkg->broken_files = 1;
			apk_warn(out, PKG_VER_FMT ": failed to preserve %s: %s",
				PKG_VER_PRINTF(pkg), ae->name, apk_extract_warning_str(r, buf, sizeof buf));
			r = 0;
		}
		switch (r) {
		case 0:
			// Hardlinks need special care for checksum
			if (!ipkg->sha256_160 && link_target_file)
				apk_dbf_digest_set(file, link_target_file->digest_alg, link_target_file->digest);
			else
				apk_dbf_digest_set(file, ae->digest.alg, ae->digest.data);

			if (ipkg->sha256_160 && S_ISLNK(ae->mode)) {
				struct apk_digest d;
				apk_digest_calc(&d, APK_DIGEST_SHA256_160,
						ae->link_target, strlen(ae->link_target));
				apk_dbf_digest_set(file, d.alg, d.data);
			} else if (file->digest_alg == APK_DIGEST_NONE && ae->digest.alg == APK_DIGEST_SHA256) {
				apk_dbf_digest_set(file, APK_DIGEST_SHA256_160, ae->digest.data);
			}
			break;
		case -APKE_NOT_EXTRACTED:
			file->broken = 1;
			break;
		case -ENOSPC:
			ret = r;
		case -APKE_UVOL_ROOT:
		case -APKE_UVOL_NOT_AVAILABLE:
		default:
			ipkg->broken_files = file->broken = 1;
			apk_err(out, PKG_VER_FMT ": failed to extract %s: %s",
				PKG_VER_PRINTF(pkg), ae->name, apk_error_str(r));
			break;
		}
	} else {
		struct apk_db_acl *expected_acl;

		apk_dbg2(out, "%s (dir)", ae->name);
		if (name.ptr[name.len-1] == '/') name.len--;

		diri = ctx->diri = find_diri(ipkg, name, NULL, &ctx->file_diri_node);
		if (!diri) diri = apk_db_install_directory_entry(ctx, name);
		diri->acl = apk_db_acl_atomize_digest(db, ae->mode, ae->uid, ae->gid, &ae->xattr_digest);
		expected_acl = diri->dir->owner ? diri->dir->owner->acl : NULL;
		apk_db_dir_apply_diri_permissions(db, diri);
		apk_db_dir_prepare(db, diri->dir, expected_acl, diri->dir->owner->acl);
	}
	ctx->installed_size += apk_calc_installed_size(ae->size);
	return ret;
}

static const struct apk_extract_ops extract_installer = {
	.v2meta = apk_db_install_v2meta,
	.v3meta = apk_db_install_v3meta,
	.script = apk_db_install_script,
	.file = apk_db_install_file,
};

static int apk_db_audit_file(struct apk_fsdir *d, apk_blob_t filename, struct apk_db_file *dbf)
{
	struct apk_file_info fi;
	int r, alg = APK_DIGEST_NONE;

	// Check file first
	if (dbf) alg = dbf->digest_alg;
	r = apk_fsdir_file_info(d, filename, APK_FI_NOFOLLOW | APK_FI_DIGEST(alg), &fi);
	if (r != 0 || alg == APK_DIGEST_NONE) return r != -ENOENT;
	if (apk_digest_cmp_blob(&fi.digest, alg, apk_dbf_digest_blob(dbf)) != 0) return 1;
	return 0;
}

static void apk_db_purge_pkg(struct apk_database *db,
			     struct apk_installed_package *ipkg,
			     int is_installed)
{
	struct apk_out *out = &db->ctx->out;
	struct apk_db_dir_instance *diri;
	struct apk_db_file *file;
	struct apk_db_file_hash_key key;
	struct apk_fsdir d;
	struct hlist_node *dc, *dn, *fc, *fn;
	unsigned long hash;
	int purge = db->ctx->flags & APK_PURGE;
	int ctrl = is_installed ? APK_FS_CTRL_DELETE : APK_FS_CTRL_CANCEL;

	hlist_for_each_entry_safe(diri, dc, dn, &ipkg->owned_dirs, pkg_dirs_list) {
		int dirclean = purge || !is_installed || apk_protect_mode_none(diri->dir->protect_mode);
		int delapknew = is_installed && !apk_protect_mode_none(diri->dir->protect_mode);
		apk_blob_t dirname = APK_BLOB_PTR_LEN(diri->dir->name, diri->dir->namelen);

		if (is_installed) diri->dir->modified = 1;
		apk_fsdir_get(&d, dirname, db->extract_flags, db->ctx, apk_pkg_ctx(ipkg->pkg));

		hlist_for_each_entry_safe(file, fc, fn, &diri->owned_files, diri_files_list) {
			key = (struct apk_db_file_hash_key) {
				.dirname = dirname,
				.filename = APK_BLOB_PTR_LEN(file->name, file->namelen),
			};
			hash = apk_blob_hash_seed(key.filename, diri->dir->hash);
			if (dirclean || apk_db_audit_file(&d, key.filename, file) == 0)
				apk_fsdir_file_control(&d, key.filename, ctrl);
			if (delapknew)
				apk_fsdir_file_control(&d, key.filename, APK_FS_CTRL_DELETE_APKNEW);

			apk_dbg2(out, DIR_FILE_FMT, DIR_FILE_PRINTF(diri->dir, file));
			__hlist_del(fc, &diri->owned_files.first);
			if (is_installed) {
				apk_hash_delete_hashed(&db->installed.files, APK_BLOB_BUF(&key), hash);
				db->installed.stats.files--;
			}
		}
		__hlist_del(dc, &ipkg->owned_dirs.first);
		apk_db_diri_free(db, diri, APK_DIR_REMOVE);
	}
}

static uint8_t apk_db_migrate_files_for_priority(struct apk_database *db,
						 struct apk_installed_package *ipkg,
						 uint8_t priority)
{
	struct apk_out *out = &db->ctx->out;
	struct apk_db_dir_instance *diri;
	struct apk_db_dir *dir;
	struct apk_db_file *file, *ofile;
	struct apk_db_file_hash_key key;
	struct hlist_node *dc, *dn, *fc, *fn;
	struct apk_fsdir d;
	unsigned long hash;
	apk_blob_t dirname;
	int r, ctrl, inetc;
	uint8_t dir_priority, next_priority = APK_FS_PRIO_MAX;

	hlist_for_each_entry_safe(diri, dc, dn, &ipkg->owned_dirs, pkg_dirs_list) {
		dir = diri->dir;
		dirname = APK_BLOB_PTR_LEN(dir->name, dir->namelen);
		apk_fsdir_get(&d, dirname, db->extract_flags, db->ctx, apk_pkg_ctx(ipkg->pkg));
		dir_priority = apk_fsdir_priority(&d);
		if (dir_priority != priority) {
			if (dir_priority > priority && dir_priority < next_priority)
				next_priority = dir_priority;
			continue;
		}
		// Used for passwd/group check later
		inetc = !apk_blob_compare(dirname, APK_BLOB_STRLIT("etc"));

		dir->modified = 1;
		hlist_for_each_entry_safe(file, fc, fn, &diri->owned_files, diri_files_list) {
			key = (struct apk_db_file_hash_key) {
				.dirname = dirname,
				.filename = APK_BLOB_PTR_LEN(file->name, file->namelen),
			};

			hash = apk_blob_hash_seed(key.filename, dir->hash);

			/* check for existing file */
			ofile = (struct apk_db_file *) apk_hash_get_hashed(
				&db->installed.files, APK_BLOB_BUF(&key), hash);

			if (!file->broken) {
				ctrl = APK_FS_CTRL_COMMIT;
				if (ofile && ofile->diri->pkg->name == NULL) {
					// File was from overlay, delete the package's version
					ctrl = APK_FS_CTRL_CANCEL;
				} else if (!apk_protect_mode_none(diri->dir->protect_mode) &&
					   apk_db_audit_file(&d, key.filename, ofile) != 0) {
					// Protected directory, and a file without db entry
					// or with local modifications. Keep the filesystem file.
					// Determine if the package's file should be kept as .apk-new
					if ((db->ctx->flags & APK_CLEAN_PROTECTED) ||
					    apk_db_audit_file(&d, key.filename, file) == 0) {
						// No .apk-new files allowed, or the file on disk has the same
						// hash as the file from new package. Keep the on disk one.
						ctrl = APK_FS_CTRL_CANCEL;
					} else {
						// All files differ. Use the package's file as .apk-new.
						ctrl = APK_FS_CTRL_APKNEW;
						apk_msg(out, PKG_VER_FMT ": installing file to " DIR_FILE_FMT ".apk-new",
						    PKG_VER_PRINTF(ipkg->pkg),
						    DIR_FILE_PRINTF(diri->dir, file));
					}
				}

				// Commit changes
				r = apk_fsdir_file_control(&d, key.filename, ctrl);
				if (r < 0) {
					apk_err(out, PKG_VER_FMT": failed to commit " DIR_FILE_FMT ": %s",
						PKG_VER_PRINTF(ipkg->pkg),
						DIR_FILE_PRINTF(diri->dir, file),
						apk_error_str(r));
					ipkg->broken_files = 1;
				} else if (inetc && ctrl == APK_FS_CTRL_COMMIT) {
					// This is called when we successfully migrated the files
					// in the filesystem; we explicitly do not care about apk-new
					// or cancel cases, as that does not change the original file
					if (!apk_blob_compare(key.filename, APK_BLOB_STRLIT("passwd")) ||
					    !apk_blob_compare(key.filename, APK_BLOB_STRLIT("group"))) {
						// Reset the idcache because we have a new passwd/group
						apk_id_cache_reset(db->id_cache);
					}
				}
			}

			// Claim ownership of the file in db
			if (ofile != file) {
				if (ofile != NULL) {
					hlist_del(&ofile->diri_files_list,
						&ofile->diri->owned_files);
					apk_hash_delete_hashed(&db->installed.files,
							       APK_BLOB_BUF(&key), hash);
				} else
					db->installed.stats.files++;

				apk_hash_insert_hashed(&db->installed.files, file, hash);
			}
		}
	}
	return next_priority;
}

static void apk_db_migrate_files(struct apk_database *db,
				 struct apk_installed_package *ipkg)
{
	for (uint8_t prio = APK_FS_PRIO_DISK; prio != APK_FS_PRIO_MAX; )
		prio = apk_db_migrate_files_for_priority(db, ipkg, prio);
}

static int apk_db_unpack_pkg(struct apk_database *db,
			     struct apk_installed_package *ipkg,
			     int upgrade, apk_progress_cb cb, void *cb_ctx,
			     char **script_args)
{
	struct apk_out *out = &db->ctx->out;
	struct install_ctx ctx;
	struct apk_istream *is = NULL;
	struct apk_repository *repo;
	struct apk_package *pkg = ipkg->pkg;
	char file[PATH_MAX];
	char cacheitem[128];
	int r, filefd = AT_FDCWD, need_copy = FALSE;

	if (!pkg->filename_ndx) {
		repo = apk_db_select_repo(db, pkg);
		if (repo == NULL) {
			r = -APKE_PACKAGE_NOT_FOUND;
			goto err_msg;
		}
		r = apk_repo_format_item(db, repo, pkg, &filefd, file, sizeof(file));
		if (r < 0)
			goto err_msg;
		if (!(pkg->repos & db->local_repos))
			need_copy = TRUE;
	} else {
		if (strlcpy(file, db->filename_array->item[pkg->filename_ndx-1], sizeof file) >= sizeof file) {
			r = -ENAMETOOLONG;
			goto err_msg;
		}
		need_copy = TRUE;
	}
	if (!apk_db_cache_active(db))
		need_copy = FALSE;

	is = apk_istream_from_fd_url(filefd, file, apk_db_url_since(db, 0));
	if (IS_ERR(is)) {
		r = PTR_ERR(is);
		if (r == -ENOENT && !pkg->filename_ndx)
			r = -APKE_INDEX_STALE;
		goto err_msg;
	}
	if (need_copy) {
		struct apk_istream *origis = is;
		apk_pkg_format_cache_pkg(APK_BLOB_BUF(cacheitem), pkg);
		is = apk_istream_tee(is, apk_ostream_to_file(db->cache_fd, cacheitem, 0644),
			APK_ISTREAM_TEE_COPY_META|APK_ISTREAM_TEE_OPTIONAL, NULL, NULL);
		if (is == origis)
			apk_warn(out, PKG_VER_FMT": unable to cache package",
				 PKG_VER_PRINTF(pkg));
	}

	ctx = (struct install_ctx) {
		.db = db,
		.pkg = pkg,
		.ipkg = ipkg,
		.script = upgrade ?
			APK_SCRIPT_PRE_UPGRADE : APK_SCRIPT_PRE_INSTALL,
		.script_args = script_args,
		.cb = cb,
		.cb_ctx = cb_ctx,
	};
	apk_extract_init(&ctx.ectx, db->ctx, &extract_installer);
	apk_extract_verify_identity(&ctx.ectx, pkg->digest_alg, apk_pkg_digest_blob(pkg));
	r = apk_extract(&ctx.ectx, is);
	if (need_copy && r == 0) pkg->repos |= BIT(APK_REPOSITORY_CACHED);
	if (r != 0) goto err_msg;

	apk_db_run_pending_script(&ctx);
	return 0;
err_msg:
	apk_err(out, PKG_VER_FMT": %s", PKG_VER_PRINTF(pkg), apk_error_str(r));
	return r;
}

int apk_db_install_pkg(struct apk_database *db, struct apk_package *oldpkg,
		       struct apk_package *newpkg, apk_progress_cb cb, void *cb_ctx)
{
	char *script_args[] = { NULL, NULL, NULL, NULL };
	struct apk_installed_package *ipkg;
	int r = 0;

	/* Upgrade script gets two args: <new-pkg> <old-pkg> */
	if (oldpkg != NULL && newpkg != NULL) {
		script_args[1] = apk_blob_cstr(*newpkg->version);
		script_args[2] = apk_blob_cstr(*oldpkg->version);
	} else {
		script_args[1] = apk_blob_cstr(*(oldpkg ? oldpkg->version : newpkg->version));
	}

	/* Just purging? */
	if (oldpkg != NULL && newpkg == NULL) {
		ipkg = oldpkg->ipkg;
		if (ipkg == NULL)
			goto ret_r;
		apk_ipkg_run_script(ipkg, db, APK_SCRIPT_PRE_DEINSTALL, script_args);
		apk_db_purge_pkg(db, ipkg, TRUE);
		apk_ipkg_run_script(ipkg, db, APK_SCRIPT_POST_DEINSTALL, script_args);
		apk_pkg_uninstall(db, oldpkg);
		goto ret_r;
	}

	/* Install the new stuff */
	ipkg = apk_pkg_install(db, newpkg);
	ipkg->run_all_triggers = 1;
	ipkg->broken_script = 0;
	ipkg->broken_files = 0;
	ipkg->broken_xattr = 0;
	if (apk_array_len(ipkg->triggers) != 0) {
		char **trigger;
		list_del(&ipkg->trigger_pkgs_list);
		list_init(&ipkg->trigger_pkgs_list);
		foreach_array_item(trigger, ipkg->triggers)
			free(*trigger);
		apk_array_truncate(ipkg->triggers, 0);
	}

	if (newpkg->installed_size != 0) {
		r = apk_db_unpack_pkg(db, ipkg, (oldpkg != NULL),
				      cb, cb_ctx, script_args);
		if (r != 0) {
			if (oldpkg != newpkg)
				apk_db_purge_pkg(db, ipkg, FALSE);
			apk_pkg_uninstall(db, newpkg);
			goto ret_r;
		}
		apk_db_migrate_files(db, ipkg);
	}

	if (oldpkg != NULL && oldpkg != newpkg && oldpkg->ipkg != NULL) {
		apk_db_purge_pkg(db, oldpkg->ipkg, TRUE);
		apk_pkg_uninstall(db, oldpkg);
	}

	apk_ipkg_run_script(
		ipkg, db,
		(oldpkg == NULL) ? APK_SCRIPT_POST_INSTALL : APK_SCRIPT_POST_UPGRADE,
		script_args);

	if (ipkg->broken_files || ipkg->broken_script)
		r = -1;
ret_r:
	free(script_args[1]);
	free(script_args[2]);
	return r;
}

struct match_ctx {
	struct apk_database *db;
	struct apk_string_array *filter;
	apk_db_foreach_name_cb cb;
	void *cb_ctx;
};

static int apk_string_match(const char *str, struct apk_string_array *filter, const char **res)
{
	char **pmatch;

	foreach_array_item(pmatch, filter) {
		if (fnmatch(*pmatch, str, FNM_CASEFOLD) == 0) {
			*res = *pmatch;
			return 1;
		}
	}
	return 0;
}

static int apk_name_match(struct apk_name *name, struct apk_string_array *filter, const char **res)
{
	if (!filter) {
		*res = NULL;
		return 1;
	}
	return apk_string_match(name->name, filter, res);
}

static int apk_pkg_match(struct apk_package *pkg, struct apk_string_array *filter, const char **res, int provides)
{
	struct apk_dependency *d;

	if (apk_name_match(pkg->name, filter, res)) return 1;
	if (!provides) return 0;
	foreach_array_item(d, pkg->provides) {
		if (apk_string_match(d->name->name, filter, res)) return 1;
	}
	return 0;
}

static int match_names(apk_hash_item item, void *pctx)
{
	struct match_ctx *ctx = (struct match_ctx *) pctx;
	struct apk_name *name = (struct apk_name *) item;
	const char *match;

	if (apk_name_match(name, ctx->filter, &match))
		return ctx->cb(ctx->db, match, name, ctx->cb_ctx);
	return 0;
}

int apk_db_foreach_matching_name(
	struct apk_database *db, struct apk_string_array *filter,
	apk_db_foreach_name_cb cb, void *ctx)
{
	char **pmatch;
	struct apk_name *name;
	struct match_ctx mctx = {
		.db = db,
		.cb = cb,
		.cb_ctx = ctx,
	};
	int r;

	if (!filter || apk_array_len(filter) == 0) goto all;

	mctx.filter = filter;
	foreach_array_item(pmatch, filter)
		if (strchr(*pmatch, '*') != NULL)
			goto all;

	foreach_array_item(pmatch, filter) {
		name = (struct apk_name *) apk_hash_get(&db->available.names, APK_BLOB_STR(*pmatch));
		r = cb(db, *pmatch, name, ctx);
		if (r) return r;
	}
	return 0;

all:
	return apk_hash_foreach(&db->available.names, match_names, &mctx);
}

static int cmp_name(const void *a, const void *b)
{
	const struct apk_name * const* na = a, * const* nb = b;
	return apk_name_cmp_display(*na, *nb);
}

static int cmp_package(const void *a, const void *b)
{
	const struct apk_package * const* pa = a, * const* pb = b;
	return apk_pkg_cmp_display(*pa, *pb);
}

static int add_name(apk_hash_item item, void *ctx)
{
	struct apk_name_array **a = ctx;
	apk_name_array_add(a, (struct apk_name *) item);
	return 0;
}

static struct apk_name_array *apk_db_sorted_names(struct apk_database *db)
{
	if (!db->sorted_names) {
		apk_name_array_resize(&db->available.sorted_names, 0, db->available.names.num_items);
		apk_hash_foreach(&db->available.names, add_name, &db->available.sorted_names);
		apk_array_qsort(db->available.sorted_names, cmp_name);
		db->sorted_names = 1;
	}
	return db->available.sorted_names;
}

struct apk_package_array *apk_db_sorted_installed_packages(struct apk_database *db)
{
	struct apk_installed_package *ipkg;

	if (!db->sorted_installed_packages) {
		db->sorted_installed_packages = 1;
		apk_package_array_resize(&db->installed.sorted_packages, 0, db->installed.stats.packages);
		list_for_each_entry(ipkg, &db->installed.packages, installed_pkgs_list)
			apk_package_array_add(&db->installed.sorted_packages, ipkg->pkg);
		apk_array_qsort(db->installed.sorted_packages, cmp_package);
	}
	return db->installed.sorted_packages;
}

int apk_db_foreach_sorted_name(struct apk_database *db, struct apk_string_array *filter,
			       apk_db_foreach_name_cb cb, void *cb_ctx)
{
	int r, walk_all = 0;
	char **pmatch;
	const char *match;
	struct apk_name *name;
	struct apk_name *results[128], **res;
	size_t i, num_res = 0;

	if (filter && apk_array_len(filter) != 0) {
		foreach_array_item(pmatch, filter) {
			name = (struct apk_name *) apk_hash_get(&db->available.names, APK_BLOB_STR(*pmatch));
			if (strchr(*pmatch, '*')) {
				walk_all = 1;
				continue;
			}
			if (!name) {
				cb(db, *pmatch, NULL, cb_ctx);
				continue;
			}
			if (walk_all) continue;
			if (num_res >= ARRAY_SIZE(results)) {
				walk_all = 1;
				continue;
			}
			results[num_res++] = name;
		}
	} else {
		filter = NULL;
		walk_all = 1;
	}

	if (walk_all) {
		struct apk_name_array *a = apk_db_sorted_names(db);
		res = a->item;
		num_res = apk_array_len(a);
	} else {
		qsort(results, num_res, sizeof results[0], cmp_name);
		res = results;
	}

	for (i = 0; i < num_res; i++) {
		name = res[i];
		if (apk_name_match(name, filter, &match)) {
			r = cb(db, match, name, cb_ctx);
			if (r) return r;
		}
	}
	return 0;
}

int __apk_db_foreach_sorted_package(struct apk_database *db, struct apk_string_array *filter,
				    apk_db_foreach_package_cb cb, void *cb_ctx, int provides)
{
	char **pmatch;
	const char *match;
	struct apk_name *name;
	struct apk_package *results[128];
	struct apk_provider *p;
	size_t i, num_res = 0;
	int r;

	if (!filter || apk_array_len(filter) == 0) {
		filter = NULL;
		goto walk_all;
	}

	foreach_array_item(pmatch, filter) {
		name = (struct apk_name *) apk_hash_get(&db->available.names, APK_BLOB_STR(*pmatch));
		if (strchr(*pmatch, '*')) goto walk_all;
		if (!name) {
			cb(db, *pmatch, NULL, cb_ctx);
			continue;
		}

		foreach_array_item(p, name->providers) {
			if (!provides && p->pkg->name != name) continue;
			if (p->pkg->seen) continue;
			p->pkg->seen = 1;
			if (num_res >= ARRAY_SIZE(results)) goto walk_all;
			results[num_res++] = p->pkg;
		}
	}
	for (i = 0; i < num_res; i++) results[i]->seen = 0;

	qsort(results, num_res, sizeof results[0], cmp_package);
	for (i = 0; i < num_res; i++) {
		if (apk_pkg_match(results[i], filter, &match, provides)) {
			r = cb(db, match, results[i], cb_ctx);
			if (r) return r;
		}
	}
	return 0;

walk_all:
	for (i = 0; i < num_res; i++) results[i]->seen = 0;

	struct apk_name_array *name_array = apk_db_sorted_names(db);
	struct apk_name **nameptr;
	foreach_array_item(nameptr, name_array) {
		name = *nameptr;
		apk_name_sorted_providers(name);
		foreach_array_item(p, name->providers) {
			if (p->pkg->name != name) continue;
			if (apk_pkg_match(p->pkg, filter, &match, provides)) {
				r = cb(db, match, p->pkg, cb_ctx);
				if (r) return r;
			}
		}
	}
	return 0;
}
