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

struct apk_database;
struct apk_name;
struct apk_provider;

#define APK_SCRIPT_INVALID		-1
#define APK_SCRIPT_PRE_INSTALL		0
#define APK_SCRIPT_POST_INSTALL		1
#define APK_SCRIPT_PRE_DEINSTALL	2
#define APK_SCRIPT_POST_DEINSTALL	3
#define APK_SCRIPT_PRE_UPGRADE		4
#define APK_SCRIPT_POST_UPGRADE		5
#define APK_SCRIPT_TRIGGER		6
#define APK_SCRIPT_MAX			7

#define APK_SIGN_VERIFY			1
#define APK_SIGN_VERIFY_IDENTITY	2
#define APK_SIGN_VERIFY_AND_GENERATE	3

#define APK_DEP_IRRELEVANT		0x01
#define APK_DEP_SATISFIES		0x02
#define APK_DEP_CONFLICTS		0x04
#define APK_FOREACH_INSTALLED		0x10
#define APK_FOREACH_MARKED		0x20
#define APK_FOREACH_NULL_MATCHES_ALL	0x40
#define APK_FOREACH_DEP			0x80
#define APK_FOREACH_GENID_MASK		0xffffff00

struct apk_sign_ctx {
	int keys_fd;
	int action;
	const EVP_MD *md;
	int num_signatures;
	int verify_error;
	unsigned char control_started : 1;
	unsigned char data_started : 1;
	unsigned char has_multiple_data_parts : 1;
	unsigned char has_data_checksum : 1;
	unsigned char control_verified : 1;
	unsigned char data_verified : 1;
	unsigned char end_seen : 1;
	char data_checksum[EVP_MAX_MD_SIZE];
	struct apk_checksum identity;
	EVP_MD_CTX *mdctx;
	EVP_MD_CTX *idctx;

	struct {
		apk_blob_t data;
		EVP_PKEY *pkey;
		char *identity;
	} signature;
};

struct apk_dependency {
	struct apk_name *name;
	apk_blob_t *version;
	unsigned broken : 1;
	unsigned repository_tag : 6;
	unsigned conflict : 1;
	unsigned result_mask : 4;
	unsigned fuzzy : 1;
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
};

struct apk_package {
	apk_hash_node hash_node;
	struct apk_name *name;
	struct apk_installed_package *ipkg;
	struct apk_dependency_array *depends, *install_if, *provides;
	apk_blob_t *version;
	size_t installed_size, size;

	union {
		struct apk_solver_package_state ss;
		int state_int;
	};
	unsigned int foreach_genid;
	unsigned short provider_priority;
	unsigned short repos;
	unsigned short filename_ndx;
	unsigned char seen : 1;
	unsigned char marked : 1;
	unsigned char uninstallable : 1;
	unsigned char cached_non_repository : 1;
	struct apk_checksum csum;

	time_t build_time;
	apk_blob_t *arch, *license, *origin, *maintainer;
	char *url, *description, *commit;
};
APK_ARRAY(apk_package_array, struct apk_package *);

#define APK_PROVIDER_FROM_PACKAGE(pkg)	  (struct apk_provider){(pkg),(pkg)->version}
#define APK_PROVIDER_FROM_PROVIDES(pkg,p) (struct apk_provider){(pkg),(p)->version}

#define PKG_VER_FMT		"%s-" BLOB_FMT
#define PKG_VER_PRINTF(pkg)	(pkg)->name->name, BLOB_PRINTF(*(pkg)->version)
#define PKG_VER_STRLEN(pkg)	(strlen(pkg->name->name) + 1 + pkg->version->len)
#define PKG_FILE_FMT		PKG_VER_FMT ".apk"
#define PKG_FILE_PRINTF(pkg)	PKG_VER_PRINTF(pkg)

extern const char *apk_script_types[];

void apk_sign_ctx_init(struct apk_sign_ctx *ctx, int action,
		       struct apk_checksum *identity, int keys_fd);
void apk_sign_ctx_free(struct apk_sign_ctx *ctx);
int apk_sign_ctx_status(struct apk_sign_ctx *ctx, int tar_rc);
int apk_sign_ctx_process_file(struct apk_sign_ctx *ctx,
			      const struct apk_file_info *fi,
			      struct apk_istream *is);
int apk_sign_ctx_parse_pkginfo_line(void *ctx, apk_blob_t line);
int apk_sign_ctx_verify_tar(void *ctx, const struct apk_file_info *fi,
			    struct apk_istream *is);
int apk_sign_ctx_mpart_cb(void *ctx, int part, apk_blob_t blob);

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

int apk_deps_write(struct apk_database *db, struct apk_dependency_array *deps,
		   struct apk_ostream *os, apk_blob_t separator);

void apk_deps_add(struct apk_dependency_array **depends, struct apk_dependency *dep);
void apk_deps_del(struct apk_dependency_array **deps, struct apk_name *name);
int apk_script_type(const char *name);

struct apk_package *apk_pkg_get_installed(struct apk_name *name);

struct apk_package *apk_pkg_new(void);
int apk_pkg_read(struct apk_database *db, const char *name,
		 struct apk_sign_ctx *ctx, struct apk_package **pkg);
void apk_pkg_free(struct apk_package *pkg);

int apk_pkg_parse_name(apk_blob_t apkname, apk_blob_t *name, apk_blob_t *version);

int apk_pkg_add_info(struct apk_database *db, struct apk_package *pkg,
		     char field, apk_blob_t value);

struct apk_installed_package *apk_pkg_install(struct apk_database *db, struct apk_package *pkg);
void apk_pkg_uninstall(struct apk_database *db, struct apk_package *pkg);

int apk_ipkg_add_script(struct apk_installed_package *ipkg,
			struct apk_istream *is,
			unsigned int type, unsigned int size);
void apk_ipkg_run_script(struct apk_installed_package *ipkg, struct apk_database *db,
			 unsigned int type, char **argv);

struct apk_package *apk_pkg_parse_index_entry(struct apk_database *db, apk_blob_t entry);
int apk_pkg_write_index_header(struct apk_package *pkg, struct apk_ostream *os);
int apk_pkg_write_index_entry(struct apk_package *pkg, struct apk_ostream *os);

int apk_pkg_version_compare(const struct apk_package *a, const struct apk_package *b);
int apk_pkg_cmp_display(const struct apk_package *a, const struct apk_package *b);

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
