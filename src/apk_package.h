/* apk_package.h - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef APK_PKG_H
#define APK_PKG_H

#include "apk_version.h"
#include "apk_hash.h"
#include "apk_io.h"
#include "apk_solver_data.h"

struct adb_obj;
struct apk_database;
struct apk_name;
struct apk_provider;
struct apk_trust;

#define APK_SCRIPT_INVALID		-1
#define APK_SCRIPT_PRE_INSTALL		0
#define APK_SCRIPT_POST_INSTALL		1
#define APK_SCRIPT_PRE_DEINSTALL	2
#define APK_SCRIPT_POST_DEINSTALL	3
#define APK_SCRIPT_PRE_UPGRADE		4
#define APK_SCRIPT_POST_UPGRADE		5
#define APK_SCRIPT_TRIGGER		6
#define APK_SCRIPT_MAX			7

#define APK_DEP_IRRELEVANT		0x01
#define APK_DEP_SATISFIES		0x02
#define APK_DEP_CONFLICTS		0x04
#define APK_FOREACH_INSTALLED		0x10
#define APK_FOREACH_MARKED		0x20
#define APK_FOREACH_NULL_MATCHES_ALL	0x40
#define APK_FOREACH_DEP			0x80
#define APK_FOREACH_GENID_MASK		0xffffff00

struct apk_dependency {
	struct apk_name *name;
	apk_blob_t *version;
	unsigned broken : 1;
	unsigned repository_tag : 6;
	unsigned conflict : 1;
	unsigned result_mask : 4;
	unsigned fuzzy : 1;
	unsigned layer : 4; // solver sets for 'world' dependencies only
};
APK_ARRAY(apk_dependency_array, struct apk_dependency);

struct apk_installed_package {
	struct apk_package *pkg;
	struct list_head installed_pkgs_list;
	struct list_head trigger_pkgs_list;
	struct hlist_head owned_dirs;
	apk_blob_t script[APK_SCRIPT_MAX];
	struct apk_string_array *triggers;
	struct apk_string_array *pending_triggers;
	struct apk_dependency_array *replaces;

	unsigned short replaces_priority;
	unsigned repository_tag : 6;
	unsigned run_all_triggers : 1;
	unsigned broken_files : 1;
	unsigned broken_script : 1;
	unsigned broken_xattr : 1;
	unsigned v3 : 1;
	unsigned sha256_160 : 1;
};

struct apk_package {
	apk_hash_node hash_node;
	unsigned int foreach_genid;
	union {
		struct apk_solver_package_state ss;
		int state_int;
		void *state_ptr;
	};
	struct apk_name *name;
	struct apk_installed_package *ipkg;
	apk_blob_t *version, *arch, *license;
	apk_blob_t *origin, *maintainer;
	char *url, *description, *commit;
	char *filename;
	struct apk_dependency_array *depends, *install_if, *provides;
	size_t installed_size, size;
	time_t build_time;
	unsigned short provider_priority;
	unsigned repos : APK_MAX_REPOS;
	unsigned marked : 1;
	unsigned uninstallable : 1;
	unsigned cached_non_repository : 1;
	unsigned layer : 4;
	struct apk_checksum csum;
};
APK_ARRAY(apk_package_array, struct apk_package *);

#define APK_PROVIDER_FROM_PACKAGE(pkg)	  (struct apk_provider){(pkg),(pkg)->version}
#define APK_PROVIDER_FROM_PROVIDES(pkg,p) (struct apk_provider){(pkg),(p)->version}

#define PKG_VER_FMT		"%s-" BLOB_FMT
#define PKG_VER_PRINTF(pkg)	pkg->name->name, BLOB_PRINTF(*pkg->version)
#define PKG_FILE_FMT		PKG_VER_FMT ".apk"
#define PKG_FILE_PRINTF(pkg)	PKG_VER_PRINTF(pkg)

extern const char *apk_script_types[];

void apk_dep_from_pkg(struct apk_dependency *dep, struct apk_database *db,
		      struct apk_package *pkg);
int apk_dep_is_materialized(struct apk_dependency *dep, struct apk_package *pkg);
int apk_dep_is_provided(struct apk_dependency *dep, struct apk_provider *p);
int apk_dep_analyze(struct apk_dependency *dep, struct apk_package *pkg);
char *apk_dep_snprintf(char *buf, size_t n, struct apk_dependency *dep);

void apk_blob_push_dep(apk_blob_t *to, struct apk_database *, struct apk_dependency *dep);
void apk_blob_push_deps(apk_blob_t *to, struct apk_database *, struct apk_dependency_array *deps);
void apk_blob_pull_dep(apk_blob_t *from, struct apk_database *, struct apk_dependency *);
void apk_blob_pull_deps(apk_blob_t *from, struct apk_database *, struct apk_dependency_array **);

int apk_deps_write_layer(struct apk_database *db, struct apk_dependency_array *deps,
			 struct apk_ostream *os, apk_blob_t separator, unsigned layer);
int apk_deps_write(struct apk_database *db, struct apk_dependency_array *deps,
		   struct apk_ostream *os, apk_blob_t separator);

void apk_dep_from_adb(struct apk_dependency *dep, struct apk_database *db, struct adb_obj *d);
void apk_deps_from_adb(struct apk_dependency_array **deps, struct apk_database *db, struct adb_obj *da);

void apk_deps_add(struct apk_dependency_array **depends, struct apk_dependency *dep);
void apk_deps_del(struct apk_dependency_array **deps, struct apk_name *name);
int apk_script_type(const char *name);

struct apk_package *apk_pkg_get_installed(struct apk_name *name);

struct apk_package *apk_pkg_new(void);
int apk_pkg_read(struct apk_database *db, const char *name, struct apk_package **pkg, int v3ok);
void apk_pkg_free(struct apk_package *pkg);

int apk_pkg_parse_name(apk_blob_t apkname, apk_blob_t *name, apk_blob_t *version);

int apk_pkg_add_info(struct apk_database *db, struct apk_package *pkg,
		     char field, apk_blob_t value);
void apk_pkg_from_adb(struct apk_database *db, struct apk_package *pkg, struct adb_obj *pkginfo);

struct apk_installed_package *apk_pkg_install(struct apk_database *db, struct apk_package *pkg);
void apk_pkg_uninstall(struct apk_database *db, struct apk_package *pkg);

int apk_ipkg_assign_script(struct apk_installed_package *ipkg, unsigned int type, apk_blob_t blob);
int apk_ipkg_add_script(struct apk_installed_package *ipkg,
			struct apk_istream *is,
			unsigned int type, unsigned int size);
void apk_ipkg_run_script(struct apk_installed_package *ipkg, struct apk_database *db,
			 unsigned int type, char **argv);

struct apk_package *apk_pkg_parse_index_entry(struct apk_database *db, apk_blob_t entry);
int apk_pkg_write_index_entry(struct apk_package *pkg, struct apk_ostream *os);

int apk_pkg_version_compare(struct apk_package *a, struct apk_package *b);

unsigned int apk_foreach_genid(void);
int apk_pkg_match_genid(struct apk_package *pkg, unsigned int match);
void apk_pkg_foreach_matching_dependency(
		struct apk_package *pkg, struct apk_dependency_array *deps,
		unsigned int match, struct apk_package *mpkg,
		void cb(struct apk_package *pkg0, struct apk_dependency *dep0, struct apk_package *pkg, void *ctx),
		void *ctx);
void apk_pkg_foreach_reverse_dependency(
		struct apk_package *pkg, unsigned int match,
		void cb(struct apk_package *pkg0, struct apk_dependency *dep0, struct apk_package *pkg, void *ctx),
		void *ctx);

#endif
