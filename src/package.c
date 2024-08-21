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

#include "apk_openssl.h"
#include <openssl/pem.h>

#include "apk_defines.h"
#include "apk_archive.h"
#include "apk_package.h"
#include "apk_database.h"
#include "apk_print.h"

static const apk_spn_match_def apk_spn_dependency_comparer = {
	[7] = (1<<4) /*<*/ | (1<<5) /*=*/ | (1<<6) /*<*/,
	[15] = (1<<6) /*~*/
};

static const apk_spn_match_def apk_spn_dependency_separator = {
	[1] = (1<<2) /*\n*/,
	[4] = (1<<0) /* */,
};

static const apk_spn_match_def apk_spn_repotag_separator = {
	[8] = (1<<0) /*@*/
};

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
	apk_blob_t bdep, bname, bop, bver = APK_BLOB_NULL, btag;
	int mask = APK_DEPMASK_ANY, conflict = 0, tag = 0, fuzzy = 0;

	/* [!]name[<,<=,<~,=,~,>~,>=,>,><]ver */
	if (APK_BLOB_IS_NULL(*b))
		goto fail;

	/* grap one token */
	if (!apk_blob_cspn(*b, apk_spn_dependency_separator, &bdep, NULL))
		bdep = *b;
	b->ptr += bdep.len;
	b->len -= bdep.len;

	/* skip also all separator chars */
	if (!apk_blob_spn(*b, apk_spn_dependency_separator, NULL, b)) {
		b->ptr += b->len;
		b->len = 0;
	}

	/* parse the version */
	if (bdep.ptr[0] == '!') {
		bdep.ptr++;
		bdep.len--;
		conflict = 1;
	}

	if (apk_blob_cspn(bdep, apk_spn_dependency_comparer, &bname, &bop)) {
		int i;

		if (mask == 0)
			goto fail;
		if (!apk_blob_spn(bop, apk_spn_dependency_comparer, &bop, &bver))
			goto fail;
		mask = 0;
		for (i = 0; i < bop.len; i++) {
			switch (bop.ptr[i]) {
			case '<':
				mask |= APK_VERSION_LESS;
				break;
			case '>':
				mask |= APK_VERSION_GREATER;
				break;
			case '~':
				mask |= APK_VERSION_FUZZY|APK_VERSION_EQUAL;
				fuzzy = TRUE;
				break;
			case '=':
				mask |= APK_VERSION_EQUAL;
				break;
			}
		}
		if ((mask & APK_DEPMASK_CHECKSUM) != APK_DEPMASK_CHECKSUM &&
		    !apk_version_validate(bver))
			goto fail;
	} else {
		bname = bdep;
		bop = APK_BLOB_NULL;
		bver = APK_BLOB_NULL;
	}

	if (apk_blob_cspn(bname, apk_spn_repotag_separator, &bname, &btag))
		tag = apk_db_get_tag_id(db, btag);

	/* convert to apk_dependency */
	name = apk_db_get_name(db, bname);
	if (name == NULL)
		goto fail;

	*dep = (struct apk_dependency){
		.name = name,
		.version = apk_atomize_dup(&db->atoms, bver),
		.repository_tag = tag,
		.result_mask = mask,
		.conflict = conflict,
		.fuzzy = fuzzy,
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
		.result_mask = APK_DEPMASK_CHECKSUM,
	};
}

static int apk_dep_match_checksum(struct apk_dependency *dep, struct apk_package *pkg)
{
	struct apk_checksum csum;
	apk_blob_t b = *dep->version;

	apk_blob_pull_csum(&b, &csum);
	if (apk_checksum_compare(&csum, &pkg->csum) == 0)
		return 1;

	return 0;
}

int apk_dep_is_provided(struct apk_dependency *dep, struct apk_provider *p)
{
	if (p == NULL || p->pkg == NULL)
		return dep->conflict;

	switch (dep->result_mask) {
	case APK_DEPMASK_CHECKSUM:
		return apk_dep_match_checksum(dep, p->pkg);
	case APK_DEPMASK_ANY:
		return !dep->conflict;
	default:
		if (p->version == &apk_atom_null)
			return dep->conflict;
		if (apk_version_compare_blob_fuzzy(*p->version, *dep->version, dep->fuzzy)
		    & dep->result_mask)
			return !dep->conflict;
		return dep->conflict;
	}
	return dep->conflict;
}

int apk_dep_is_materialized(struct apk_dependency *dep, struct apk_package *pkg)
{
	if (pkg == NULL)
		return dep->conflict;
	if (dep->name != pkg->name)
		return dep->conflict;

	switch (dep->result_mask) {
	case APK_DEPMASK_CHECKSUM:
		return apk_dep_match_checksum(dep, pkg);
	case APK_DEPMASK_ANY:
		return !dep->conflict;
	default:
		if (apk_version_compare_blob_fuzzy(*pkg->version, *dep->version, dep->fuzzy)
		    & dep->result_mask)
			return !dep->conflict;
		return dep->conflict;
	}
	return dep->conflict;
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
	int result_mask = dep->result_mask;

	if (dep->conflict)
		apk_blob_push_blob(to, APK_BLOB_PTR_LEN("!", 1));

	apk_blob_push_blob(to, APK_BLOB_STR(dep->name->name));
	if (dep->repository_tag && db != NULL)
		apk_blob_push_blob(to, db->repo_tags[dep->repository_tag].tag);
	if (!APK_BLOB_IS_NULL(*dep->version)) {
		apk_blob_push_blob(to, APK_BLOB_STR(apk_version_op_string(result_mask)));
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

int apk_deps_write(struct apk_database *db, struct apk_dependency_array *deps, struct apk_ostream *os, apk_blob_t separator)
{
	apk_blob_t blob;
	char tmp[256];
	int i, n = 0;

	if (deps == NULL)
		return 0;

	for (i = 0; i < deps->num; i++) {
		blob = APK_BLOB_BUF(tmp);
		if (i)
			apk_blob_push_blob(&blob, separator);
		apk_blob_push_dep(&blob, db, &deps->item[i]);

		blob = apk_blob_pushed(APK_BLOB_BUF(tmp), blob);
		if (APK_BLOB_IS_NULL(blob) || 
		    apk_ostream_write(os, blob.ptr, blob.len) != blob.len)
			return -1;

		n += blob.len;
	}

	return n;
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

void apk_sign_ctx_init(struct apk_sign_ctx *ctx, int action,
		       struct apk_checksum *identity, int keys_fd)
{
	memset(ctx, 0, sizeof(struct apk_sign_ctx));
	ctx->keys_fd = keys_fd;
	ctx->action = action;
	ctx->verify_error = -ENOKEY;
	switch (action) {
	case APK_SIGN_VERIFY_AND_GENERATE:
		ctx->idctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(ctx->idctx, EVP_sha1(), NULL);
		break;
	case APK_SIGN_VERIFY:
		break;
	case APK_SIGN_VERIFY_IDENTITY:
		memcpy(&ctx->identity, identity, sizeof(ctx->identity));
		break;
	default:
		assert(!"valid sign mode");
		break;
	}
	ctx->md = EVP_sha1();
	ctx->mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx->mdctx, ctx->md, NULL);
}

void apk_sign_ctx_free(struct apk_sign_ctx *ctx)
{
	free(ctx->signature.data.ptr);
	EVP_PKEY_free(ctx->signature.pkey);
	EVP_MD_CTX_free(ctx->mdctx);
	EVP_MD_CTX_free(ctx->idctx);
}

int apk_sign_ctx_status(struct apk_sign_ctx *ctx, int tar_rc)
{
	if (ctx->has_multiple_data_parts)
		apk_warning("Support for packages with multiple data parts "
			"will be dropped in apk-tools 3.");
	if (ctx->has_pkginfo && !ctx->has_data_checksum)
		apk_warning("Support for packages without datahash "
			"will be dropped in apk-tools 3.");
	if (tar_rc < 0 && tar_rc != -ECANCELED) return tar_rc;
	if (tar_rc == 0 && (!ctx->data_verified || !ctx->end_seen)) tar_rc = -EBADMSG;
	if (!ctx->verify_error) return tar_rc;
	if (ctx->verify_error == -ENOKEY && (apk_flags & APK_ALLOW_UNTRUSTED)) return tar_rc;
	return ctx->verify_error;
}

static int check_signing_key_trust(struct apk_sign_ctx *sctx)
{
	switch (sctx->action) {
	case APK_SIGN_VERIFY:
	case APK_SIGN_VERIFY_AND_GENERATE:
		if (sctx->signature.pkey == NULL) {
			if (apk_flags & APK_ALLOW_UNTRUSTED)
				break;
			return -ENOKEY;
		}
	}
	return 0;
}

int apk_sign_ctx_process_file(struct apk_sign_ctx *ctx,
			      const struct apk_file_info *fi,
			      struct apk_istream *is)
{
	static struct {
		char type[8];
		unsigned int nid;
	} signature_type[] = {
		{ "RSA512", NID_sha512 },
		{ "RSA256", NID_sha256 },
		{ "RSA", NID_sha1 },
		{ "DSA", NID_dsa },
	};
	const EVP_MD *md = NULL;
	const char *name = NULL;
	BIO *bio;
	int r, i, fd;

	if (ctx->data_started)
		return 1;

	if (fi->name[0] != '.' || strchr(fi->name, '/') != NULL) {
		/* APKv1.0 compatibility - first non-hidden file is
		 * considered to start the data section of the file.
		 * This does not make any sense if the file has v2.0
		 * style .PKGINFO */
		if (ctx->has_data_checksum)
			return -ENOMSG;
		/* Error out early if identity part is missing */
		if (ctx->action == APK_SIGN_VERIFY_IDENTITY)
			return -EKEYREJECTED;
		ctx->data_started = 1;
		ctx->control_started = 1;
		r = check_signing_key_trust(ctx);
		if (r < 0)
			return r;
		return 1;
	}

	if (ctx->control_started)
		return 1;

	if (strncmp(fi->name, ".SIGN.", 6) != 0) {
		ctx->control_started = 1;
		return 1;
	}

	/* By this point, we must be handling a signature file */
	ctx->num_signatures++;

	/* Already found a signature by a trusted key; no need to keep searching */
	if (ctx->action == APK_SIGN_VERIFY_IDENTITY) return 0;
	if (ctx->signature.pkey != NULL) return 0;
	if (ctx->keys_fd < 0) return 0;

	for (i = 0; i < ARRAY_SIZE(signature_type); i++) {
		size_t slen = strlen(signature_type[i].type);
		if (strncmp(&fi->name[6], signature_type[i].type, slen) == 0 &&
		    fi->name[6+slen] == '.') {
			md = EVP_get_digestbynid(signature_type[i].nid);
			name = &fi->name[6+slen+1];
			break;
		}
	}
	if (!md) return 0;

	fd = openat(ctx->keys_fd, name, O_RDONLY|O_CLOEXEC);
	if (fd < 0) return 0;

	bio = BIO_new_fp(fdopen(fd, "r"), BIO_CLOSE);
	ctx->signature.pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (ctx->signature.pkey != NULL) {
		ctx->md = md;
		apk_blob_from_istream(is, fi->size, &ctx->signature.data);
	}
	BIO_free(bio);

	return 0;
}

int apk_sign_ctx_parse_pkginfo_line(void *ctx, apk_blob_t line)
{
	struct apk_sign_ctx *sctx = (struct apk_sign_ctx *) ctx;
	apk_blob_t l, r;

	sctx->has_pkginfo = 1;
	if (!sctx->control_started || sctx->data_started)
		return 0;

	if (line.ptr == NULL || line.len < 1 || line.ptr[0] == '#')
		return 0;

	if (!apk_blob_split(line, APK_BLOB_STR(" = "), &l, &r))
		return 0;

	if (apk_blob_compare(APK_BLOB_STR("datahash"), l) == 0) {
		sctx->has_data_checksum = 1;
		sctx->md = EVP_sha256();
		apk_blob_pull_hexdump(
			&r, APK_BLOB_PTR_LEN(sctx->data_checksum,
					     EVP_MD_size(sctx->md)));
	}

	return 0;
}

int apk_sign_ctx_verify_tar(void *sctx, const struct apk_file_info *fi,
			    struct apk_istream *is)
{
	struct apk_sign_ctx *ctx = (struct apk_sign_ctx *) sctx;
	int r;

	r = apk_sign_ctx_process_file(ctx, fi, is);
	if (r <= 0)
		return r;

	if (!ctx->control_started || ctx->data_started)
		return 0;

	if (strcmp(fi->name, ".PKGINFO") == 0) {
		apk_blob_t l, token = APK_BLOB_STR("\n");
		while (!APK_BLOB_IS_NULL(l = apk_istream_get_delim(is, token)))
			apk_sign_ctx_parse_pkginfo_line(ctx, l);
	}

	return 0;
}

/*	apk_sign_ctx_mpart_cb() handles hashing archives and checking signatures, but
	it can't do it alone. apk_sign_ctx_process_file() must be in the loop to
	actually select which signature is to be verified and load the corresponding
	public key into the context object, and	apk_sign_ctx_parse_pkginfo_line()
	needs to be called when handling the .PKGINFO file to find any applicable
	datahash and load it into the context for this function to check against. */
int apk_sign_ctx_mpart_cb(void *ctx, int part, apk_blob_t data)
{
	struct apk_sign_ctx *sctx = (struct apk_sign_ctx *) ctx;
	unsigned char calculated[EVP_MAX_MD_SIZE];
	int r, end_of_control;

	if (sctx->end_seen || sctx->data_verified) return -EBADMSG;
	if (part == APK_MPART_BOUNDARY && sctx->data_started) {
		sctx->has_multiple_data_parts = 1;
		return 0;
	}
	if (part == APK_MPART_END) sctx->end_seen = 1;
	if (part == APK_MPART_DATA) {
		/* Update digest with the data now. Only _DATA callbacks can have data. */
		if (EVP_DigestUpdate(sctx->mdctx, data.ptr, data.len) != 1)
			return -EAPKCRYPTO;

		/* Update identity generated also if needed. */
		if (sctx->idctx && (!sctx->has_data_checksum || !sctx->data_started)) {
			if (EVP_DigestUpdate(sctx->idctx, data.ptr, data.len) != 1)
				return -EAPKCRYPTO;
		}
		return 0;
	}
	if (data.len) return -EBADMSG;

	/* Still in signature blocks? */
	if (!sctx->control_started) {
		if (part == APK_MPART_END) return -EKEYREJECTED;
		if (EVP_DigestInit_ex(sctx->mdctx, sctx->md, NULL) != 1)
			return -EAPKCRYPTO;
		if (sctx->idctx && EVP_DigestInit_ex(sctx->idctx, EVP_sha1(), NULL) != 1)
			return -EAPKCRYPTO;
		return 0;
	}

	/* Grab state and mark all remaining block as data */
	end_of_control = (sctx->data_started == 0);
	sctx->data_started = 1;

	/* End of control-block and control does not have data checksum? */
	if (sctx->has_data_checksum == 0 && end_of_control && part != APK_MPART_END)
		return 0;

	if (sctx->has_data_checksum && !end_of_control) {
		/* End of data-block with a checksum read from the control block */
		if (EVP_DigestFinal_ex(sctx->mdctx, calculated, NULL) != 1)
			return -EAPKCRYPTO;
		if (EVP_MD_CTX_size(sctx->mdctx) == 0 ||
		    memcmp(calculated, sctx->data_checksum,
		           EVP_MD_CTX_size(sctx->mdctx)) != 0)
			return -EKEYREJECTED;
		sctx->data_verified = 1;
		if (!(apk_flags & APK_ALLOW_UNTRUSTED) &&
		    !sctx->control_verified)
			return -ENOKEY;
		return 0;
	}

	/* Either end of control block with a data checksum or end
	 * of the data block following a control block without a data
	 * checksum. In either case, we're checking a signature. */
	r = check_signing_key_trust(sctx);
	if (r < 0)
		return r;

	switch (sctx->action) {
	case APK_SIGN_VERIFY_AND_GENERATE:
		/* Package identity is the checksum */
		sctx->identity.type = EVP_MD_CTX_size(sctx->idctx);
		if (EVP_DigestFinal_ex(sctx->idctx, sctx->identity.data, NULL) != 1)
			return -EAPKCRYPTO;
		/* Fall through to check signature */
	case APK_SIGN_VERIFY:
		if (sctx->signature.pkey != NULL) {
			if (EVP_VerifyFinal(sctx->mdctx,
				(unsigned char *) sctx->signature.data.ptr,
				sctx->signature.data.len,
				sctx->signature.pkey) == 1)
				sctx->verify_error = 0;
			else
				sctx->verify_error = -EKEYREJECTED;
		}
		if (sctx->verify_error) {
			if (sctx->verify_error != -ENOKEY ||
			    !(apk_flags & APK_ALLOW_UNTRUSTED))
				return sctx->verify_error;
		}
		sctx->control_verified = 1;
		if (!sctx->has_data_checksum && part == APK_MPART_END)
			sctx->data_verified = 1;
		if (sctx->action == APK_SIGN_VERIFY_AND_GENERATE && sctx->has_data_checksum)
			return -ECANCELED;
		break;
	case APK_SIGN_VERIFY_IDENTITY:
		/* Reset digest for hashing data */
		if (EVP_DigestFinal_ex(sctx->mdctx, calculated, NULL) != 1)
			return -EAPKCRYPTO;
		if (memcmp(calculated, sctx->identity.data,
			   sctx->identity.type) != 0)
			return -EKEYREJECTED;
		sctx->verify_error = 0;
		sctx->control_verified = 1;
		if (!sctx->has_data_checksum && part == APK_MPART_END)
			sctx->data_verified = 1;
		break;
	}
	if (EVP_DigestInit_ex(sctx->mdctx, sctx->md, NULL) != 1)
		return -EAPKCRYPTO;
	if (sctx->idctx && EVP_DigestInit_ex(sctx->idctx, EVP_sha1(), NULL) != 1)
		return -EAPKCRYPTO;
	return 0;
}

struct read_info_ctx {
	struct apk_database *db;
	struct apk_package *pkg;
	struct apk_sign_ctx *sctx;
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
		return -EAPKFORMAT;
	return 0;
}

static int read_info_line(void *ctx, apk_blob_t line)
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
	struct read_info_ctx *ri = (struct read_info_ctx *) ctx;
	apk_blob_t l, r;
	int i;

	if (line.ptr == NULL || line.len < 1 || line.ptr[0] == '#')
		return 0;

	if (!apk_blob_split(line, APK_BLOB_STR(" = "), &l, &r))
		return 0;

	for (i = 0; i < ARRAY_SIZE(fields); i++)
		if (apk_blob_compare(APK_BLOB_STR(fields[i].str), l) == 0)
			return apk_pkg_add_info(ri->db, ri->pkg, fields[i].field, r);

	apk_sign_ctx_parse_pkginfo_line(ri->sctx, line);
	return 0;
}

static int read_info_entry(void *ctx, const struct apk_file_info *ae,
			   struct apk_istream *is)
{
	struct read_info_ctx *ri = (struct read_info_ctx *) ctx;
	struct apk_package *pkg = ri->pkg;
	int r;

	r = apk_sign_ctx_process_file(ri->sctx, ae, is);
	if (r <= 0)
		return r;

	if (!ri->sctx->control_started || ri->sctx->data_started)
		return 0;

	if (strcmp(ae->name, ".PKGINFO") == 0) {
		/* APK 2.0 format */
		apk_blob_t l, token = APK_BLOB_STR("\n");
		while (!APK_BLOB_IS_NULL(l = apk_istream_get_delim(is, token))) {
			r = read_info_line(ctx, l);
			if (r < 0) return r;
		}
	} else if (strcmp(ae->name, ".INSTALL") == 0) {
		apk_warning("Package '%s-" BLOB_FMT "' contains deprecated .INSTALL",
				pkg->name->name, BLOB_PRINTF(*pkg->version));
	}

	return 0;
}

int apk_pkg_read(struct apk_database *db, const char *file,
	         struct apk_sign_ctx *sctx, struct apk_package **pkg)
{
	struct read_info_ctx ctx;
	struct apk_file_info fi;
	int r;

	r = apk_fileinfo_get(AT_FDCWD, file, APK_CHECKSUM_NONE, &fi, &db->atoms);
	if (r != 0)
		return r;

	memset(&ctx, 0, sizeof(ctx));
	ctx.db = db;
	ctx.sctx = sctx;
	ctx.pkg = apk_pkg_new();
	r = -ENOMEM;
	if (ctx.pkg == NULL)
		goto err;

	ctx.pkg->size = fi.size;

	r = apk_tar_parse(
		apk_istream_gunzip_mpart(apk_istream_from_file(AT_FDCWD, file), apk_sign_ctx_mpart_cb, sctx),
		read_info_entry, &ctx, &db->id_cache);
	r = apk_sign_ctx_status(sctx, r);
	if (r < 0 && r != -ECANCELED)
		goto err;
	if (ctx.pkg->name == NULL || ctx.pkg->uninstallable) {
		r = -ENOTSUP;
		goto err;
	}
	if (sctx->action != APK_SIGN_VERIFY)
		ctx.pkg->csum = sctx->identity;
	*apk_string_array_add(&db->filename_array) = strdup(file);
	ctx.pkg->filename_ndx = db->filename_array->num;

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
	if (pkg == NULL) return;

	apk_pkg_uninstall(NULL, pkg);
	apk_dependency_array_free(&pkg->depends);
	apk_dependency_array_free(&pkg->provides);
	apk_dependency_array_free(&pkg->install_if);
	if (pkg->url) free(pkg->url);
	if (pkg->description) free(pkg->description);
	if (pkg->commit) free(pkg->commit);
	free(pkg);
}

static int apk_ipkg_assign_script(struct apk_installed_package *ipkg, unsigned int type, apk_blob_t b)
{
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

static inline int make_dirs(int root_fd, const char *dirname, mode_t dirmode, mode_t parentmode)
{
	char parentdir[PATH_MAX], *slash;

	if (faccessat(root_fd, dirname, F_OK, 0) == 0) return 0;
	if (mkdirat(root_fd, dirname, dirmode) == 0) return 0;
	if (errno != ENOENT || !parentmode) return -1;

	slash = strrchr(dirname, '/');
	if (!slash || slash == dirname || slash-dirname+1 >= sizeof parentdir) return -1;
	strlcpy(parentdir, dirname, slash-dirname+1);
	if (make_dirs(root_fd, parentdir, parentmode, parentmode) < 0) return -1;
	return mkdirat(root_fd, dirname, dirmode);
}

void apk_ipkg_run_script(struct apk_installed_package *ipkg,
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
	struct apk_package *pkg = ipkg->pkg;
	char fn[PATH_MAX];
	int fd, root_fd = db->root_fd;

	if (type >= APK_SCRIPT_MAX || ipkg->script[type].ptr == NULL)
		return;

	argv[0] = (char *) apk_script_types[type];

	snprintf(fn, sizeof(fn), "%s/" PKG_VER_FMT ".%s",
		script_exec_dir, PKG_VER_PRINTF(pkg),
		apk_script_types[type]);

	if ((apk_flags & (APK_NO_SCRIPTS | APK_SIMULATE)) != 0)
		return;

	apk_message("Executing %s", &fn[strlen(script_exec_dir)+1]);
	fd = openat(root_fd, fn, O_CREAT|O_RDWR|O_TRUNC|O_CLOEXEC, 0755);
	if (fd < 0) {
		make_dirs(root_fd, script_exec_dir, 0700, 0755);
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
	apk_id_cache_reset(&db->id_cache);

	goto cleanup;

err_log:
	apk_error("%s: failed to execute: %s", &fn[15], apk_error_str(errno));
err:
	ipkg->broken_script = 1;
cleanup:
	unlinkat(root_fd, fn, 0);
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
	struct read_info_ctx ctx;

	ctx.pkg = apk_pkg_new();
	if (ctx.pkg == NULL)
		return NULL;

	ctx.db = db;

	apk_blob_for_each_segment(blob, "\n", parse_index_line, &ctx);

	if (ctx.pkg->name == NULL) {
		apk_pkg_free(ctx.pkg);
		apk_error("Failed to parse index entry: " BLOB_FMT,
			  BLOB_PRINTF(blob));
		ctx.pkg = NULL;
	}

	return ctx.pkg;
}

static int write_depends(struct apk_ostream *os, const char *field,
			 struct apk_dependency_array *deps)
{
	int r;

	if (deps->num == 0) return 0;
	if (apk_ostream_write(os, field, 2) != 2) return -1;
	if ((r = apk_deps_write(NULL, deps, os, APK_BLOB_PTR_LEN(" ", 1))) < 0) return r;
	if (apk_ostream_write(os, "\n", 1) != 1) return -1;
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

	if (APK_BLOB_IS_NULL(bbuf)) {
		apk_error("Metadata for package " PKG_VER_FMT " is too long.",
			  PKG_VER_PRINTF(info));
		return -ENOBUFS;
	}

	bbuf = apk_blob_pushed(APK_BLOB_BUF(buf), bbuf);
	if (apk_ostream_write(os, bbuf.ptr, bbuf.len) != bbuf.len ||
	    write_depends(os, "D:", info->depends) ||
	    write_depends(os, "p:", info->provides) ||
	    write_depends(os, "i:", info->install_if))
		return -EIO;

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
	if (a->version == b->version) return APK_VERSION_EQUAL;
	return apk_version_compare_blob(*a->version, *b->version);
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
