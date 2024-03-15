/* package.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "apk_openssl.h"
#include <openssl/pem.h>

#include "apk_defines.h"
#include "apk_package.h"
#include "apk_database.h"
#include "apk_ctype.h"
#include "apk_print.h"
#include "apk_extract.h"
#include "apk_adb.h"

struct apk_package *apk_pkg_get_installed(struct apk_name *name)
{
	struct apk_provider *p;

	foreach_array_item(p, name->providers)
		if (p->pkg->name == name && p->pkg->ipkg != NULL)
			return p->pkg;

	return NULL;
}

struct apk_package *apk_pkg_new(void)
{
	struct apk_package *pkg;

	pkg = calloc(1, sizeof(struct apk_package));
	if (pkg != NULL) {
		apk_dependency_array_init(&pkg->depends);
		apk_dependency_array_init(&pkg->install_if);
		apk_dependency_array_init(&pkg->provides);
	}

	return pkg;
}

struct apk_installed_package *apk_pkg_install(struct apk_database *db,
					      struct apk_package *pkg)
{
	struct apk_installed_package *ipkg;

	if (pkg->ipkg != NULL)
		return pkg->ipkg;

	pkg->ipkg = ipkg = calloc(1, sizeof(struct apk_installed_package));
	ipkg->pkg = pkg;
	apk_string_array_init(&ipkg->triggers);
	apk_string_array_init(&ipkg->pending_triggers);
	apk_dependency_array_init(&ipkg->replaces);

	/* Overlay override information resides in a nameless package */
	if (pkg->name != NULL) {
		db->sorted_installed_packages = 0;
		db->installed.stats.packages++;
		db->installed.stats.bytes += pkg->installed_size;
		list_add_tail(&ipkg->installed_pkgs_list,
			      &db->installed.packages);
	}

	return ipkg;
}

void apk_pkg_uninstall(struct apk_database *db, struct apk_package *pkg)
{
	struct apk_installed_package *ipkg = pkg->ipkg;
	char **trigger;
	int i;

	if (ipkg == NULL)
		return;

	if (db != NULL) {
		db->sorted_installed_packages = 0;
		db->installed.stats.packages--;
		db->installed.stats.bytes -= pkg->installed_size;
	}

	list_del(&ipkg->installed_pkgs_list);

	if (ipkg->triggers->num) {
		list_del(&ipkg->trigger_pkgs_list);
		list_init(&ipkg->trigger_pkgs_list);
		foreach_array_item(trigger, ipkg->triggers)
			free(*trigger);
	}
	apk_string_array_free(&ipkg->triggers);
	apk_string_array_free(&ipkg->pending_triggers);
	apk_dependency_array_free(&ipkg->replaces);

	for (i = 0; i < APK_SCRIPT_MAX; i++)
		if (ipkg->script[i].ptr != NULL)
			free(ipkg->script[i].ptr);
	free(ipkg);
	pkg->ipkg = NULL;
}

int apk_pkg_parse_name(apk_blob_t apkname,
		       apk_blob_t *name,
		       apk_blob_t *version)
{
	int i, dash = 0;

	if (APK_BLOB_IS_NULL(apkname))
		return -1;

	for (i = apkname.len - 2; i >= 0; i--) {
		if (apkname.ptr[i] != '-')
			continue;
		if (isdigit(apkname.ptr[i+1]))
			break;
		if (++dash >= 2)
			return -1;
	}
	if (i < 0)
		return -1;

	if (name != NULL)
		*name = APK_BLOB_PTR_LEN(apkname.ptr, i);
	if (version != NULL)
		*version = APK_BLOB_PTR_PTR(&apkname.ptr[i+1],
					    &apkname.ptr[apkname.len-1]);

	return 0;
}

int apk_dep_parse(apk_blob_t spec, apk_blob_t *name, int *rop, apk_blob_t *version)
{
	apk_blob_t bop;
	int op = 0;

	/* [!]name[[op]ver] */
	if (APK_BLOB_IS_NULL(spec)) goto fail;
	if (apk_blob_pull_blob_match(&spec, APK_BLOB_STRLIT("!")))
		op |= APK_VERSION_CONFLICT;
	if (apk_blob_cspn(spec, APK_CTYPE_DEPENDENCY_COMPARER, name, &bop)) {
		if (!apk_blob_spn(bop, APK_CTYPE_DEPENDENCY_COMPARER, &bop, version)) goto fail;
		op |= apk_version_result_mask_blob(bop);
		if ((op & ~APK_VERSION_CONFLICT) == 0) goto fail;
		if ((op & APK_DEPMASK_CHECKSUM) != APK_DEPMASK_CHECKSUM &&
		    !apk_version_validate(*version)) goto fail;
	} else {
		*name = spec;
		op |= APK_DEPMASK_ANY;
		*version = APK_BLOB_NULL;
	}
	*rop = op;
	return 0;
fail:
	*name = APK_BLOB_NULL;
	*version = APK_BLOB_NULL;
	*rop = APK_DEPMASK_ANY;
	return -APKE_DEPENDENCY_FORMAT;
}

void apk_deps_add(struct apk_dependency_array **depends, struct apk_dependency *dep)
{
	struct apk_dependency *d0;

	if (*depends) {
		foreach_array_item(d0, *depends) {
			if (d0->name == dep->name) {
				*d0 = *dep;
				return;
			}
		}
	}
	*apk_dependency_array_add(depends) = *dep;
}

void apk_deps_del(struct apk_dependency_array **pdeps, struct apk_name *name)
{
	struct apk_dependency_array *deps = *pdeps;
	struct apk_dependency *d0;

	if (deps == NULL)
		return;

	foreach_array_item(d0, deps) {
		if (d0->name == name) {
			*d0 = deps->item[deps->num - 1];
			apk_dependency_array_resize(pdeps, deps->num - 1);
			break;
		}
	}
}

void apk_blob_pull_dep(apk_blob_t *b, struct apk_database *db, struct apk_dependency *dep)
{
	struct apk_name *name;
	apk_blob_t bdep, bname, bver, btag;
	int op, tag = 0;

	/* grap one token, and skip all separators */
	if (APK_BLOB_IS_NULL(*b)) goto fail;
	apk_blob_cspn(*b, APK_CTYPE_DEPENDENCY_SEPARATOR, &bdep, b);
	apk_blob_spn(*b, APK_CTYPE_DEPENDENCY_SEPARATOR, NULL, b);

	if (apk_dep_parse(bdep, &bname, &op, &bver) != 0) goto fail;
	if (apk_blob_split(bname, APK_BLOB_STRLIT("@"), &bname, &btag))
		tag = apk_db_get_tag_id(db, btag);

	/* convert to apk_dependency */
	name = apk_db_get_name(db, bname);
	if (name == NULL) goto fail;

	*dep = (struct apk_dependency){
		.name = name,
		.version = apk_atomize_dup(&db->atoms, bver),
		.repository_tag = tag,
		.op = op,
	};
	return;
fail:
	*dep = (struct apk_dependency){ .name = NULL };
	*b = APK_BLOB_NULL;
}

void apk_blob_pull_deps(apk_blob_t *b, struct apk_database *db, struct apk_dependency_array **deps)
{
	struct apk_dependency dep;

	while (b->len > 0) {
		apk_blob_pull_dep(b, db, &dep);
		if (APK_BLOB_IS_NULL(*b) || dep.name == NULL)
			break;

		*apk_dependency_array_add(deps) = dep;
	}
}

void apk_dep_from_pkg(struct apk_dependency *dep, struct apk_database *db,
		      struct apk_package *pkg)
{
	char buf[64];
	apk_blob_t b = APK_BLOB_BUF(buf);

	apk_blob_push_csum(&b, &pkg->csum);
	b = apk_blob_pushed(APK_BLOB_BUF(buf), b);

	*dep = (struct apk_dependency) {
		.name = pkg->name,
		.version = apk_atomize_dup(&db->atoms, b),
		.op = APK_DEPMASK_CHECKSUM,
	};
}

static const int apk_checksum_compare(const struct apk_checksum *a, const struct apk_checksum *b)
{
	return apk_blob_compare(APK_BLOB_PTR_LEN((char *) a->data, a->type),
				APK_BLOB_PTR_LEN((char *) b->data, b->type));
}

static int apk_dep_match_checksum(const struct apk_dependency *dep, const struct apk_package *pkg)
{
	struct apk_checksum csum;
	apk_blob_t b = *dep->version;

	apk_blob_pull_csum(&b, &csum);
	return apk_checksum_compare(&csum, &pkg->csum) == 0;
}

int apk_dep_is_provided(const struct apk_dependency *dep, const struct apk_provider *p)
{
	if (p == NULL || p->pkg == NULL) return apk_dep_conflict(dep);
	if (dep->op == APK_DEPMASK_CHECKSUM) return apk_dep_match_checksum(dep, p->pkg);
	return apk_version_match(*p->version, dep->op, *dep->version);
}

int apk_dep_is_materialized(const struct apk_dependency *dep, const struct apk_package *pkg)
{
	if (pkg == NULL || dep->name != pkg->name) return apk_dep_conflict(dep);
	if (dep->op == APK_DEPMASK_CHECKSUM) return apk_dep_match_checksum(dep, pkg);
	return apk_version_match(*pkg->version, dep->op, *dep->version);
}

int apk_dep_analyze(struct apk_dependency *dep, struct apk_package *pkg)
{
	struct apk_dependency *p;
	struct apk_provider provider;

	if (pkg == NULL)
		return APK_DEP_IRRELEVANT;

	if (dep->name == pkg->name)
		return apk_dep_is_materialized(dep, pkg) ? APK_DEP_SATISFIES : APK_DEP_CONFLICTS;

	foreach_array_item(p, pkg->provides) {
		if (p->name != dep->name)
			continue;
		provider = APK_PROVIDER_FROM_PROVIDES(pkg, p);
		return apk_dep_is_provided(dep, &provider) ? APK_DEP_SATISFIES : APK_DEP_CONFLICTS;
	}

	return APK_DEP_IRRELEVANT;
}

char *apk_dep_snprintf(char *buf, size_t n, struct apk_dependency *dep)
{
	apk_blob_t b = APK_BLOB_PTR_LEN(buf, n);
	apk_blob_push_dep(&b, NULL, dep);
	if (b.len)
		apk_blob_push_blob(&b, APK_BLOB_PTR_LEN("", 1));
	else
		b.ptr[-1] = 0;
	return buf;
}

void apk_blob_push_dep(apk_blob_t *to, struct apk_database *db, struct apk_dependency *dep)
{
	if (apk_dep_conflict(dep))
		apk_blob_push_blob(to, APK_BLOB_PTR_LEN("!", 1));

	apk_blob_push_blob(to, APK_BLOB_STR(dep->name->name));
	if (dep->repository_tag && db != NULL)
		apk_blob_push_blob(to, db->repo_tags[dep->repository_tag].tag);
	if (!APK_BLOB_IS_NULL(*dep->version)) {
		apk_blob_push_blob(to, APK_BLOB_STR(apk_version_op_string(dep->op)));
		apk_blob_push_blob(to, *dep->version);
	}
}

void apk_blob_push_deps(apk_blob_t *to, struct apk_database *db, struct apk_dependency_array *deps)
{
	int i;

	if (deps == NULL)
		return;

	for (i = 0; i < deps->num; i++) {
		if (i)
			apk_blob_push_blob(to, APK_BLOB_PTR_LEN(" ", 1));
		apk_blob_push_dep(to, db, &deps->item[i]);
	}
}

int apk_deps_write_layer(struct apk_database *db, struct apk_dependency_array *deps, struct apk_ostream *os, apk_blob_t separator, unsigned layer)
{
	apk_blob_t blob;
	char tmp[256];
	int i, n = 0;

	if (deps == NULL)
		return 0;

	for (i = 0; i < deps->num; i++) {
		if (layer != -1 && deps->item[i].layer != layer) continue;

		blob = APK_BLOB_BUF(tmp);
		if (n) apk_blob_push_blob(&blob, separator);
		apk_blob_push_dep(&blob, db, &deps->item[i]);

		blob = apk_blob_pushed(APK_BLOB_BUF(tmp), blob);
		if (APK_BLOB_IS_NULL(blob) || 
		    apk_ostream_write(os, blob.ptr, blob.len) < 0)
			return -1;

		n += blob.len;
	}

	return n;
}

int apk_deps_write(struct apk_database *db, struct apk_dependency_array *deps, struct apk_ostream *os, apk_blob_t separator)
{
	return apk_deps_write_layer(db, deps, os, separator, -1);
}

void apk_dep_from_adb(struct apk_dependency *dep, struct apk_database *db, struct adb_obj *d)
{
	int op = adb_ro_int(d, ADBI_DEP_MATCH);
	*dep = (struct apk_dependency) {
		.name = apk_db_get_name(db, adb_ro_blob(d, ADBI_DEP_NAME)),
		.version = apk_atomize_dup(&db->atoms, adb_ro_blob(d, ADBI_DEP_VERSION)),
		.op = (op & ~APK_VERSION_CONFLICT) ?: op|APK_VERSION_EQUAL,
	};
}

void apk_deps_from_adb(struct apk_dependency_array **deps, struct apk_database *db, struct adb_obj *da)
{
	struct adb_obj obj;
	int i;

	for (i = ADBI_FIRST; i <= adb_ra_num(da); i++) {
		struct apk_dependency *d = apk_dependency_array_add(deps);
		adb_ro_obj(da, i, &obj);
		apk_dep_from_adb(d, db, &obj);
	}
}

const char *apk_script_types[] = {
	[APK_SCRIPT_PRE_INSTALL]	= "pre-install",
	[APK_SCRIPT_POST_INSTALL]	= "post-install",
	[APK_SCRIPT_PRE_DEINSTALL]	= "pre-deinstall",
	[APK_SCRIPT_POST_DEINSTALL]	= "post-deinstall",
	[APK_SCRIPT_PRE_UPGRADE]	= "pre-upgrade",
	[APK_SCRIPT_POST_UPGRADE]	= "post-upgrade",
	[APK_SCRIPT_TRIGGER]		= "trigger",
};

int apk_script_type(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(apk_script_types); i++)
		if (apk_script_types[i] &&
		    strcmp(apk_script_types[i], name) == 0)
			return i;

	return APK_SCRIPT_INVALID;
}

struct read_info_ctx {
	struct apk_database *db;
	struct apk_package *pkg;
	struct apk_extract_ctx ectx;
	int v3ok;
};

int apk_pkg_add_info(struct apk_database *db, struct apk_package *pkg,
		     char field, apk_blob_t value)
{
	switch (field) {
	case 'P':
		pkg->name = apk_db_get_name(db, value);
		break;
	case 'V':
		pkg->version = apk_atomize_dup(&db->atoms, value);
		break;
	case 'T':
		pkg->description = apk_blob_cstr(value);
		break;
	case 'U':
		pkg->url = apk_blob_cstr(value);
		break;
	case 'L':
		pkg->license = apk_atomize_dup(&db->atoms, value);
		break;
	case 'A':
		pkg->arch = apk_atomize_dup(&db->atoms, value);
		break;
	case 'D':
		apk_blob_pull_deps(&value, db, &pkg->depends);
		break;
	case 'C':
		apk_blob_pull_csum(&value, &pkg->csum);
		break;
	case 'S':
		pkg->size = apk_blob_pull_uint(&value, 10);
		break;
	case 'I':
		pkg->installed_size = apk_blob_pull_uint(&value, 10);
		break;
	case 'p':
		apk_blob_pull_deps(&value, db, &pkg->provides);
		break;
	case 'i':
		apk_blob_pull_deps(&value, db, &pkg->install_if);
		break;
	case 'o':
		pkg->origin = apk_atomize_dup(&db->atoms, value);
		break;
	case 'm':
		pkg->maintainer = apk_atomize_dup(&db->atoms, value);
		break;
	case 't':
		pkg->build_time = apk_blob_pull_uint(&value, 10);
		break;
	case 'c':
		pkg->commit = apk_blob_cstr(value);
		break;
	case 'k':
		pkg->provider_priority = apk_blob_pull_uint(&value, 10);
		break;
	case 'F': case 'M': case 'R': case 'Z': case 'r': case 'q':
	case 'a': case 's': case 'f':
		/* installed db entries which are handled in database.c */
		return 1;
	default:
		/* lower case index entries are safe to be ignored */
		if (!islower(field)) {
			pkg->uninstallable = 1;
			db->compat_notinstallable = 1;
		}
		db->compat_newfeatures = 1;
		return 2;
	}
	if (APK_BLOB_IS_NULL(value))
		return -APKE_V2PKG_FORMAT;
	return 0;
}

static char *commit_id(apk_blob_t b)
{
	char buf[80];
	apk_blob_t to = APK_BLOB_BUF(buf);

	apk_blob_push_hexdump(&to, b);
	to = apk_blob_pushed(APK_BLOB_BUF(buf), to);
	if (APK_BLOB_IS_NULL(to)) return NULL;
	return apk_blob_cstr(to);
}

void apk_pkg_from_adb(struct apk_database *db, struct apk_package *pkg, struct adb_obj *pkginfo)
{
	struct adb_obj obj;
	apk_blob_t uid;

	uid = adb_ro_blob(pkginfo, ADBI_PI_UNIQUE_ID);
	if (uid.len >= APK_CHECKSUM_SHA1) {
		pkg->csum.type = APK_CHECKSUM_SHA1;
		memcpy(pkg->csum.data, uid.ptr, uid.len);
	}

	pkg->name = apk_db_get_name(db, adb_ro_blob(pkginfo, ADBI_PI_NAME));
	pkg->version = apk_atomize_dup(&db->atoms, adb_ro_blob(pkginfo, ADBI_PI_VERSION));
	pkg->description = apk_blob_cstr(adb_ro_blob(pkginfo, ADBI_PI_DESCRIPTION));
	pkg->url = apk_blob_cstr(adb_ro_blob(pkginfo, ADBI_PI_URL));
	pkg->license = apk_atomize_dup(&db->atoms, adb_ro_blob(pkginfo, ADBI_PI_LICENSE));
	pkg->arch = apk_atomize_dup(&db->atoms, adb_ro_blob(pkginfo, ADBI_PI_ARCH));
	pkg->installed_size = adb_ro_int(pkginfo, ADBI_PI_INSTALLED_SIZE);
	pkg->size = adb_ro_int(pkginfo, ADBI_PI_FILE_SIZE);
	pkg->provider_priority = adb_ro_int(pkginfo, ADBI_PI_PROVIDER_PRIORITY);
	pkg->origin = apk_atomize_dup(&db->atoms, adb_ro_blob(pkginfo, ADBI_PI_ORIGIN));
	pkg->maintainer = apk_atomize_dup(&db->atoms, adb_ro_blob(pkginfo, ADBI_PI_MAINTAINER));
	pkg->build_time = adb_ro_int(pkginfo, ADBI_PI_BUILD_TIME);
	pkg->commit = commit_id(adb_ro_blob(pkginfo, ADBI_PI_REPO_COMMIT));
	pkg->layer = adb_ro_int(pkginfo, ADBI_PI_LAYER);

	apk_deps_from_adb(&pkg->depends, db, adb_ro_obj(pkginfo, ADBI_PI_DEPENDS, &obj));
	apk_deps_from_adb(&pkg->provides, db, adb_ro_obj(pkginfo, ADBI_PI_PROVIDES, &obj));
	apk_deps_from_adb(&pkg->install_if, db, adb_ro_obj(pkginfo, ADBI_PI_INSTALL_IF, &obj));
}

static int read_info_line(struct read_info_ctx *ri, apk_blob_t line)
{
	static struct {
		const char *str;
		char field;
	} fields[] = {
		{ "pkgname",	'P' },
		{ "pkgver", 	'V' },
		{ "pkgdesc",	'T' },
		{ "url",	'U' },
		{ "size",	'I' },
		{ "license",	'L' },
		{ "arch",	'A' },
		{ "depend",	'D' },
		{ "install_if",	'i' },
		{ "provides",	'p' },
		{ "origin",	'o' },
		{ "maintainer",	'm' },
		{ "builddate",	't' },
		{ "commit",	'c' },
		{ "provider_priority", 'k' },
	};
	apk_blob_t l, r;
	int i;

	if (line.ptr == NULL || line.len < 1 || line.ptr[0] == '#')
		return 0;

	if (!apk_blob_split(line, APK_BLOB_STR(" = "), &l, &r))
		return 0;

	apk_extract_v2_control(&ri->ectx, l, r);

	for (i = 0; i < ARRAY_SIZE(fields); i++)
		if (apk_blob_compare(APK_BLOB_STR(fields[i].str), l) == 0)
			return apk_pkg_add_info(ri->db, ri->pkg, fields[i].field, r);

	return 0;
}

static int apk_pkg_v2meta(struct apk_extract_ctx *ectx, struct apk_istream *is)
{
	struct read_info_ctx *ri = container_of(ectx, struct read_info_ctx, ectx);
	apk_blob_t l, token = APK_BLOB_STR("\n");
	int r;

	while (apk_istream_get_delim(is, token, &l) == 0) {
		r = read_info_line(ri, l);
		if (r < 0) return r;
	}

	return 0;
}

static int apk_pkg_v3meta(struct apk_extract_ctx *ectx, struct adb_obj *pkg)
{
	struct read_info_ctx *ri = container_of(ectx, struct read_info_ctx, ectx);
	struct adb_obj pkginfo;

	if (!ri->v3ok) return -APKE_FORMAT_NOT_SUPPORTED;

	adb_ro_obj(pkg, ADBI_PKG_PKGINFO, &pkginfo);
	apk_pkg_from_adb(ri->db, ri->pkg, &pkginfo);

	return -ECANCELED;
}

static const struct apk_extract_ops extract_pkgmeta_ops = {
	.v2meta = apk_pkg_v2meta,
	.v3meta = apk_pkg_v3meta,
};

int apk_pkg_read(struct apk_database *db, const char *file, struct apk_package **pkg, int v3ok)
{
	struct read_info_ctx ctx = {
		.db = db,
		.v3ok = v3ok,
	};
	struct apk_file_info fi;
	int r;

	r = apk_fileinfo_get(AT_FDCWD, file, 0, &fi, &db->atoms);
	if (r != 0)
		return r;

	ctx.pkg = apk_pkg_new();
	r = -ENOMEM;
	if (ctx.pkg == NULL)
		goto err;

	ctx.pkg->size = fi.size;
	apk_extract_init(&ctx.ectx, db->ctx, &extract_pkgmeta_ops);
	apk_extract_generate_identity(&ctx.ectx, &ctx.pkg->csum);

	r = apk_extract(&ctx.ectx, apk_istream_from_file(AT_FDCWD, file));
	if (r < 0) goto err;
	if (ctx.pkg->csum.type == APK_CHECKSUM_NONE ||
	    ctx.pkg->name == NULL ||
	    ctx.pkg->uninstallable) {
		r = -APKE_FORMAT_NOT_SUPPORTED;
		goto err;
	}
	ctx.pkg->filename = strdup(file);

	ctx.pkg = apk_db_pkg_add(db, ctx.pkg);
	if (pkg != NULL)
		*pkg = ctx.pkg;
	return 0;
err:
	apk_pkg_free(ctx.pkg);
	return r;
}

void apk_pkg_free(struct apk_package *pkg)
{
	if (!pkg) return;

	apk_pkg_uninstall(NULL, pkg);
	apk_dependency_array_free(&pkg->depends);
	apk_dependency_array_free(&pkg->provides);
	apk_dependency_array_free(&pkg->install_if);
	if (pkg->url) free(pkg->url);
	if (pkg->description) free(pkg->description);
	if (pkg->commit) free(pkg->commit);
	if (pkg->filename) free(pkg->filename);
	free(pkg);
}

int apk_ipkg_assign_script(struct apk_installed_package *ipkg, unsigned int type, apk_blob_t b)
{
	if (APK_BLOB_IS_NULL(b)) return -1;
	if (type >= APK_SCRIPT_MAX) {
		free(b.ptr);
		return -1;
	}
	if (ipkg->script[type].ptr) free(ipkg->script[type].ptr);
	ipkg->script[type] = b;
	return 0;
}

int apk_ipkg_add_script(struct apk_installed_package *ipkg,
			struct apk_istream *is,
			unsigned int type, unsigned int size)
{
	apk_blob_t b;
	apk_blob_from_istream(is, size, &b);
	return apk_ipkg_assign_script(ipkg, type, b);
}

#ifdef __linux__
static inline int make_device_tree(struct apk_database *db)
{
	if (faccessat(db->root_fd, "dev", F_OK, 0) == 0) return 0;
	if (mkdirat(db->root_fd, "dev", 0755) < 0 ||
	    mknodat(db->root_fd, "dev/null", S_IFCHR | 0666, makedev(1, 3)) < 0 ||
	    mknodat(db->root_fd, "dev/zero", S_IFCHR | 0666, makedev(1, 5)) < 0 ||
	    mknodat(db->root_fd, "dev/random", S_IFCHR | 0666, makedev(1, 8)) < 0 ||
	    mknodat(db->root_fd, "dev/urandom", S_IFCHR | 0666, makedev(1, 9)) < 0 ||
	    mknodat(db->root_fd, "dev/console", S_IFCHR | 0600, makedev(5, 1)) < 0)
		return -1;
	return 0;
}
#else
static inline int make_device_tree(struct apk_database *db)
{
	(void) db;
	return 0;
}
#endif

int apk_ipkg_run_script(struct apk_installed_package *ipkg,
			struct apk_database *db,
			unsigned int type, char **argv)
{
	// script_exec_dir is the directory to which the script is extracted,
	// executed from, and removed. It needs to not be 'noexec' mounted, and
	// preferably a tmpfs disk, or something that could be wiped in boot.
	// Originally this was /tmp, but it is often suggested to be 'noexec'.
	// Then changed ro /var/cache/misc, but that is also often 'noexec'.
	// /run was consider as it's tmpfs, but it also might be changing to 'noexec'.
	// So use for now /lib/apk/exec even if it is not of temporary nature.
	static const char script_exec_dir[] = "lib/apk/exec";
	struct apk_out *out = &db->ctx->out;
	struct apk_package *pkg = ipkg->pkg;
	char fn[PATH_MAX];
	int fd, root_fd = db->root_fd, ret = 0;

	if (type >= APK_SCRIPT_MAX || ipkg->script[type].ptr == NULL)
		return 0;

	argv[0] = (char *) apk_script_types[type];

	snprintf(fn, sizeof(fn), "%s/" PKG_VER_FMT ".%s",
		script_exec_dir, PKG_VER_PRINTF(pkg),
		apk_script_types[type]);

	if ((db->ctx->flags & (APK_NO_SCRIPTS | APK_SIMULATE)) != 0)
		return 0;

	if (!db->script_dirs_checked) {
		if (apk_make_dirs(root_fd, "tmp", 01777, 0) <0 ||
		    apk_make_dirs(root_fd, script_exec_dir, 0700, 0755) < 0) {
			apk_err(out, "failed to prepare dirs for hook scripts: %s",
				apk_error_str(errno));
			goto err;
		}
		if (make_device_tree(db) < 0) {
			apk_warn(out, "failed to create initial device nodes for scripts: %s",
				apk_error_str(errno));
		}
		db->script_dirs_checked = 1;
	}

	apk_msg(out, "Executing %s", &fn[strlen(script_exec_dir)+1]);
	fd = openat(root_fd, fn, O_CREAT|O_RDWR|O_TRUNC|O_CLOEXEC, 0755);
	if (fd < 0) {
		fd = openat(root_fd, fn, O_CREAT|O_RDWR|O_TRUNC|O_CLOEXEC, 0755);
		if (fd < 0) goto err_log;
	}
	if (write(fd, ipkg->script[type].ptr, ipkg->script[type].len) < 0) {
		close(fd);
		goto err_log;
	}
	close(fd);

	if (apk_db_run_script(db, fn, argv) < 0)
		goto err;

	/* Script may have done something that changes id cache contents */
	apk_id_cache_reset(db->id_cache);

	goto cleanup;

err_log:
	apk_err(out, "%s: failed to execute: %s", &fn[strlen(script_exec_dir)+1], apk_error_str(errno));
err:
	ipkg->broken_script = 1;
	ret = 1;
cleanup:
	unlinkat(root_fd, fn, 0);
	return ret;
}

static int parse_index_line(void *ctx, apk_blob_t line)
{
	struct read_info_ctx *ri = (struct read_info_ctx *) ctx;

	if (line.len < 3 || line.ptr[1] != ':')
		return 0;

	apk_pkg_add_info(ri->db, ri->pkg, line.ptr[0], APK_BLOB_PTR_LEN(line.ptr+2, line.len-2));
	return 0;
}

struct apk_package *apk_pkg_parse_index_entry(struct apk_database *db, apk_blob_t blob)
{
	struct apk_out *out = &db->ctx->out;
	struct read_info_ctx ctx;

	ctx.pkg = apk_pkg_new();
	if (ctx.pkg == NULL)
		return NULL;

	ctx.db = db;

	apk_blob_for_each_segment(blob, "\n", parse_index_line, &ctx);

	if (ctx.pkg->name == NULL) {
		apk_pkg_free(ctx.pkg);
		apk_err(out, "Failed to parse index entry: " BLOB_FMT, BLOB_PRINTF(blob));
		ctx.pkg = NULL;
	}

	return ctx.pkg;
}

static int write_depends(struct apk_ostream *os, const char *field,
			 struct apk_dependency_array *deps)
{
	int r;

	if (deps->num == 0) return 0;
	if (apk_ostream_write(os, field, 2) < 0) return -1;
	if ((r = apk_deps_write(NULL, deps, os, APK_BLOB_PTR_LEN(" ", 1))) < 0) return r;
	if (apk_ostream_write(os, "\n", 1) < 0) return -1;
	return 0;
}

int apk_pkg_write_index_header(struct apk_package *info, struct apk_ostream *os)
{
	char buf[2048];
	apk_blob_t bbuf = APK_BLOB_BUF(buf);

	apk_blob_push_blob(&bbuf, APK_BLOB_STR("C:"));
	apk_blob_push_csum(&bbuf, &info->csum);
	apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nP:"));
	apk_blob_push_blob(&bbuf, APK_BLOB_STR(info->name->name));
	apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nV:"));
	apk_blob_push_blob(&bbuf, *info->version);
	if (info->arch != NULL) {
		apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nA:"));
		apk_blob_push_blob(&bbuf, *info->arch);
	}
	apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nS:"));
	apk_blob_push_uint(&bbuf, info->size, 10);
	apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nI:"));
	apk_blob_push_uint(&bbuf, info->installed_size, 10);
	apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nT:"));
	apk_blob_push_blob(&bbuf, APK_BLOB_STR(info->description));
	apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nU:"));
	apk_blob_push_blob(&bbuf, APK_BLOB_STR(info->url));
	apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nL:"));
	apk_blob_push_blob(&bbuf, *info->license);
	if (info->origin) {
		apk_blob_push_blob(&bbuf, APK_BLOB_STR("\no:"));
		apk_blob_push_blob(&bbuf, *info->origin);
	}
	if (info->maintainer) {
		apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nm:"));
		apk_blob_push_blob(&bbuf, *info->maintainer);
	}
	if (info->build_time) {
		apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nt:"));
		apk_blob_push_uint(&bbuf, info->build_time, 10);
	}
	if (info->commit) {
		apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nc:"));
		apk_blob_push_blob(&bbuf, APK_BLOB_STR(info->commit));
	}
	if (info->provider_priority) {
		apk_blob_push_blob(&bbuf, APK_BLOB_STR("\nk:"));
		apk_blob_push_uint(&bbuf, info->provider_priority, 10);
	}
	apk_blob_push_blob(&bbuf, APK_BLOB_STR("\n"));

	if (APK_BLOB_IS_NULL(bbuf))
		return apk_ostream_cancel(os, -ENOBUFS);

	bbuf = apk_blob_pushed(APK_BLOB_BUF(buf), bbuf);
	if (apk_ostream_write(os, bbuf.ptr, bbuf.len) < 0 ||
	    write_depends(os, "D:", info->depends) ||
	    write_depends(os, "p:", info->provides) ||
	    write_depends(os, "i:", info->install_if))
		return apk_ostream_cancel(os, -EIO);

	return 0;
}

int apk_pkg_write_index_entry(struct apk_package *pkg, struct apk_ostream *os)
{
	int r = apk_pkg_write_index_header(pkg, os);
	if (r < 0) return r;
	return apk_ostream_write(os, "\n", 1);
}

int apk_pkg_version_compare(const struct apk_package *a, const struct apk_package *b)
{
	if (a->version == b->version)
		return APK_VERSION_EQUAL;

	return apk_version_compare(*a->version, *b->version);
}

int apk_pkg_cmp_display(const struct apk_package *a, const struct apk_package *b)
{
	if (a->name != b->name)
		return apk_name_cmp_display(a->name, b->name);
	switch (apk_pkg_version_compare(a, b)) {
	case APK_VERSION_LESS:
		return -1;
	case APK_VERSION_GREATER:
		return 1;
	default:
		return 0;
	}
}

unsigned int apk_foreach_genid(void)
{
	static unsigned int foreach_genid;
	foreach_genid += (~APK_FOREACH_GENID_MASK) + 1;
	return foreach_genid;
}

int apk_pkg_match_genid(struct apk_package *pkg, unsigned int match)
{
	unsigned int genid = match & APK_FOREACH_GENID_MASK;
	if (pkg && genid) {
		if (pkg->foreach_genid >= genid)
			return 1;
		pkg->foreach_genid = genid;
	}
	return 0;
}

void apk_pkg_foreach_matching_dependency(
		struct apk_package *pkg, struct apk_dependency_array *deps,
		unsigned int match, struct apk_package *mpkg,
		void cb(struct apk_package *pkg0, struct apk_dependency *dep0, struct apk_package *pkg, void *ctx),
		void *ctx)
{
	unsigned int one_dep_only = (match & APK_FOREACH_GENID_MASK) && !(match & APK_FOREACH_DEP);
	struct apk_dependency *d;

	if (apk_pkg_match_genid(pkg, match)) return;

	foreach_array_item(d, deps) {
		if (apk_dep_analyze(d, mpkg) & match) {
			cb(pkg, d, mpkg, ctx);
			if (one_dep_only) break;
		}
	}
}

static void foreach_reverse_dependency(
		struct apk_package *pkg,
		struct apk_name_array *rdepends,
		unsigned int match,
		void cb(struct apk_package *pkg0, struct apk_dependency *dep0, struct apk_package *pkg, void *ctx),
		void *ctx)
{
	unsigned int marked = match & APK_FOREACH_MARKED;
	unsigned int installed = match & APK_FOREACH_INSTALLED;
	unsigned int one_dep_only = (match & APK_FOREACH_GENID_MASK) && !(match & APK_FOREACH_DEP);
	struct apk_name **pname0, *name0;
	struct apk_provider *p0;
	struct apk_package *pkg0;
	struct apk_dependency *d0;

	foreach_array_item(pname0, rdepends) {
		name0 = *pname0;
		foreach_array_item(p0, name0->providers) {
			pkg0 = p0->pkg;
			if (installed && pkg0->ipkg == NULL) continue;
			if (marked && !pkg0->marked) continue;
			if (apk_pkg_match_genid(pkg0, match)) continue;
			foreach_array_item(d0, pkg0->depends) {
				if (apk_dep_analyze(d0, pkg) & match) {
					cb(pkg0, d0, pkg, ctx);
					if (one_dep_only) break;
				}
			}
		}
	}
}

void apk_pkg_foreach_reverse_dependency(
		struct apk_package *pkg, unsigned int match,
		void cb(struct apk_package *pkg0, struct apk_dependency *dep0, struct apk_package *pkg, void *ctx),
		void *ctx)
{
	struct apk_dependency *p;

	foreach_reverse_dependency(pkg, pkg->name->rdepends, match, cb, ctx);
	foreach_array_item(p, pkg->provides)
		foreach_reverse_dependency(pkg, p->name->rdepends, match, cb, ctx);
}
