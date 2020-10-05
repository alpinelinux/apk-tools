#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>

#include "apk_adb.h"
#include "apk_applet.h"

struct conv_script {
	struct list_head script_node;
	char csum_len;
	char csum[32];
	int type;
	size_t size;
	apk_blob_t *triggers;
	char script[];
};

struct conv_ctx {
	struct apk_database *db;
	struct adb_obj pkgs;

	struct list_head script_head;
	struct adb dbi;
	struct adb dbp;
	int found;
};

static int read_script(void *pctx, const struct apk_file_info *ae, struct apk_istream *is)
{
	struct conv_ctx *ctx = pctx;
	struct conv_script *s;
	char *fncsum, *fnaction;
	apk_blob_t blob;
	int type;

	/* The scripts db expects regular file with name in format:
	 * pkgname-version.identity.action */
	if (!S_ISREG(ae->mode)) return 0;
	fnaction = memrchr(ae->name, '.', strlen(ae->name));
	if (!fnaction || fnaction == ae->name) return 0;
	fncsum = memrchr(ae->name, '.', fnaction - ae->name - 1);
	if (!fncsum) return 0;
	fnaction++;
	fncsum++;

	/* Parse it */
	type = adb_s_field_by_name(&schema_scripts, fnaction);
	if (!type) return 0;

	blob = APK_BLOB_PTR_PTR(fncsum, fnaction - 2);
	if (blob.len+1 > sizeof s->csum) return 0;

	s = malloc(sizeof(struct conv_script) + ae->size);
	if (!s) return 0;
	memset(s, 0, sizeof *s);
	list_init(&s->script_node);
	s->csum_len = blob.len;
	memcpy(s->csum, blob.ptr, blob.len);
	s->type = type;
	s->size = ae->size;
	apk_istream_read(is, s->script, s->size);
	if (s->script[s->size-1] == '\n') {
		while (s->size > 1 && s->script[s->size-2] == '\n')
			s->size--;
	}
	list_add_tail(&s->script_node, &ctx->script_head);

	return 0;
}

static struct conv_script *find_pkg(struct conv_ctx *ctx, apk_blob_t identity, int type)
{
	struct conv_script *s;
	list_for_each_entry(s, &ctx->script_head, script_node)
		if (apk_blob_compare(APK_BLOB_PTR_LEN(s->csum, s->csum_len), identity) == 0)
			return s;
	return 0;
}

static int read_triggers(struct conv_ctx *ctx, struct apk_istream *is)
{
	apk_blob_t l, r, nl = APK_BLOB_STR("\n"), spc = APK_BLOB_STR(" ");
	struct conv_script *s;

	if (IS_ERR(is)) return PTR_ERR(is);

	while (!APK_BLOB_IS_NULL(l = apk_istream_get_delim(is, nl))) {
		if (!apk_blob_split(l, spc, &l, &r)) continue;
		s = find_pkg(ctx, l, ADBI_SCRPT_TRIGGER);
		if (!s) continue;

		s->triggers = apk_atomize_dup(&ctx->db->atoms, r);
	}

	apk_istream_close(is);
	return 0;
}

static void convert_idb(struct conv_ctx *ctx, struct apk_istream *is)
{
	struct apk_checksum csum;
	struct adb_obj pkg, pkginfo, files, file, paths, path, scripts, triggers;
	apk_blob_t l, val, spc = APK_BLOB_STR(" "), nl = APK_BLOB_STR("\n");
	struct conv_script *s;
	int i;

	adb_wo_alloca(&scripts, &schema_scripts, &ctx->dbp);
	adb_wo_alloca(&triggers, &schema_string_array, &ctx->dbp);
	adb_wo_alloca(&pkginfo, &schema_pkginfo, &ctx->dbp);
	adb_wo_alloca(&files, &schema_file_array, &ctx->dbp);
	adb_wo_alloca(&file, &schema_file, &ctx->dbp);
	adb_wo_alloca(&paths, &schema_path_array, &ctx->dbp);
	adb_wo_alloca(&path, &schema_path, &ctx->dbp);
	adb_wo_alloca(&pkg, &schema_package, &ctx->dbp);

	while (!APK_BLOB_IS_NULL(l = apk_istream_get_delim(is, nl))) {
		if (l.len < 2) {
			adb_wa_append_obj(&files, &file);
			adb_wo_obj(&path, ADBI_FI_FILES, &files);
			adb_wa_append_obj(&paths, &path);

			adb_wo_obj(&pkg, ADBI_PKG_PKGINFO, &pkginfo);
			adb_wo_obj(&pkg, ADBI_PKG_PATHS, &paths);
			adb_w_rootobj(&pkg);

			adb_wa_append(&ctx->pkgs, adb_w_adb(&ctx->dbi, &ctx->dbp));
			adb_reset(&ctx->dbp);
			continue;
		}
		val = APK_BLOB_PTR_LEN(l.ptr+2, l.len-2);
		i = adb_pkg_field_index(l.ptr[0]);
		if (i > 0) adb_wo_pkginfo(&pkginfo, i, val);

		switch (l.ptr[0]) {
		case 'C': // pkg checksum
			list_for_each_entry(s, &ctx->script_head, script_node) {
				if (apk_blob_compare(APK_BLOB_PTR_LEN(s->csum, s->csum_len), val) != 0)
					continue;

				adb_wo_blob(&scripts, s->type, APK_BLOB_PTR_LEN(s->script, s->size));
				if (s->type == ADBI_SCRPT_TRIGGER && s->triggers) {
					apk_blob_t r = *s->triggers, l = *s->triggers;
					while (apk_blob_split(r, spc, &l, &r))
						adb_wa_append(&triggers, adb_w_blob(&ctx->dbp, l));
					adb_wa_append(&triggers, adb_w_blob(&ctx->dbp, r));
					adb_wo_obj(&pkg, ADBI_PKG_TRIGGERS, &triggers);
				}
			}
			adb_wo_obj(&pkg, ADBI_PKG_SCRIPTS, &scripts);
			break;
		case 'F': // directory name
			adb_wa_append_obj(&files, &file);
			adb_wo_obj(&path, ADBI_FI_FILES, &files);
			adb_wa_append_obj(&paths, &path);

			adb_wo_blob(&path, ADBI_FI_NAME, val);
			break;
		case 'M': // directory mode: uid:gid:mode:xattrcsum
			adb_wo_int(&path, ADBI_FI_UID, apk_blob_pull_uint(&val, 10));
			apk_blob_pull_char(&val, ':');
			adb_wo_int(&path, ADBI_FI_GID, apk_blob_pull_uint(&val, 10));
			apk_blob_pull_char(&val, ':');
			adb_wo_int(&path, ADBI_FI_MODE, apk_blob_pull_uint(&val, 8));
			break;
		case 'R': // file name
			adb_wa_append_obj(&files, &file);
			adb_wo_blob(&file, ADBI_FI_NAME, val);
			break;
		case 'a': // file mode: uid:gid:mode:xattrcsum
			adb_wo_int(&file, ADBI_FI_UID, apk_blob_pull_uint(&val, 10));
			apk_blob_pull_char(&val, ':');
			adb_wo_int(&file, ADBI_FI_GID, apk_blob_pull_uint(&val, 10));
			apk_blob_pull_char(&val, ':');
			adb_wo_int(&file, ADBI_FI_MODE, apk_blob_pull_uint(&val, 8));
			break;
		case 'Z': // file content hash
			apk_blob_pull_csum(&val, &csum);
			adb_wo_blob(&file, ADBI_FI_HASHES, APK_BLOB_CSUM(csum));
			break;
		case 's': // repository_tag
		case 'f': // fix required (flags: fsx)
			/* FIXME */
			break;
		default:
			break;
		}
	}
}

static int conv_main(void *pctx, struct apk_database *db, struct apk_string_array *args)
{
	struct conv_ctx *ctx = pctx;
	struct adb_obj idb;
	int r;

	ctx->db = db;
	list_init(&ctx->script_head);

	adb_w_init_alloca(&ctx->dbi, ADB_SCHEMA_INSTALLED_DB, 10);
	adb_w_init_alloca(&ctx->dbp, ADB_SCHEMA_PACKAGE, 1000);
	adb_wo_alloca(&idb, &schema_idb, &ctx->dbi);
	adb_wo_alloca(&ctx->pkgs, &schema_package_adb_array, &ctx->dbi);

	apk_tar_parse(
		apk_istream_from_file(db->root_fd, "lib/apk/db/scripts.tar"),
		read_script, ctx, &db->id_cache);

	read_triggers(ctx, apk_istream_from_file(db->root_fd, "lib/apk/db/triggers"));

	convert_idb(ctx, apk_istream_from_file(db->root_fd, "lib/apk/db/installed"));

	adb_wo_obj(&idb, ADBI_IDB_PACKAGES, &ctx->pkgs);
	adb_w_rootobj(&idb);

	r = adb_c_create(
		//apk_ostream_to_file(db->root_fd, "lib/apk/db/installed.adb", 0644),
		apk_ostream_to_file(AT_FDCWD, "installed.adb", 0644),
		&ctx->dbi, &db->trust);
	if (r == 0) {
		// unlink old files
	}

	adb_free(&ctx->dbi);
	adb_free(&ctx->dbp);

	return r;
}

static struct apk_applet apk_convdb = {
	.name = "convdb",
	.open_flags = APK_OPENF_READ | APK_OPENF_NO_STATE | APK_OPENF_NO_REPOS,
	.context_size = sizeof(struct conv_ctx),
	.optgroups = { &optgroup_global, &optgroup_signing },
	.main = conv_main,
};
APK_DEFINE_APPLET(apk_convdb);
