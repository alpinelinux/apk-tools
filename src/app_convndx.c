#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "apk_adb.h"
#include "apk_applet.h"

struct conv_ctx {
	struct apk_ctx *ac;
	struct adb_obj pkgs;
	struct adb dbi;
	struct apk_sign_ctx sctx;
	int found;
};

static void convert_index(struct conv_ctx *ctx, struct apk_istream *is)
{
	struct adb_obj pkginfo;
	apk_blob_t token = APK_BLOB_STR("\n"), l;
	int i;

	adb_wo_alloca(&pkginfo, &schema_pkginfo, &ctx->dbi);

	while (!APK_BLOB_IS_NULL(l = apk_istream_get_delim(is, token))) {
		if (l.len < 2) {
			adb_wa_append_obj(&ctx->pkgs, &pkginfo);
			continue;
		}
		i = adb_pkg_field_index(l.ptr[0]);
		if (i > 0) adb_wo_pkginfo(&pkginfo, i, APK_BLOB_PTR_LEN(l.ptr+2, l.len-2));
	}
}

static int load_apkindex(void *sctx, const struct apk_file_info *fi,
			 struct apk_istream *is)
{
	struct conv_ctx *ctx = sctx;
	int r;

	r = apk_sign_ctx_process_file(&ctx->sctx, fi, is);
	if (r <= 0) return r;

	if (strcmp(fi->name, "APKINDEX") == 0) {
		ctx->found = 1;
		convert_index(ctx, is);
		apk_istream_close(is);
	}

	return 0;
}

static int load_index(struct conv_ctx *ctx, struct apk_istream *is)
{
	int r = 0;

	if (IS_ERR_OR_NULL(is)) return is ? PTR_ERR(is) : -EINVAL;

	ctx->found = 0;
	apk_sign_ctx_init(&ctx->sctx, APK_SIGN_VERIFY, NULL, apk_ctx_get_trust(ctx->ac));
	r = apk_tar_parse(
		apk_istream_gunzip_mpart(is, apk_sign_ctx_mpart_cb, &ctx->sctx),
		load_apkindex, ctx, apk_ctx_get_id_cache(ctx->ac));
	apk_sign_ctx_free(&ctx->sctx);
	if (r >= 0 && ctx->found == 0) r = -APKE_V2NDX_FORMAT;

	return r;
}

static int conv_main(void *pctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	char **arg;
	struct conv_ctx *ctx = pctx;
	struct apk_trust *trust = apk_ctx_get_trust(ac);
	struct apk_out *out = &ac->out;
	struct adb_obj ndx;
	int r;

	ctx->ac = ac;
	adb_w_init_alloca(&ctx->dbi, ADB_SCHEMA_INDEX, 1000);
	adb_wo_alloca(&ndx, &schema_index, &ctx->dbi);
	adb_wo_alloca(&ctx->pkgs, &schema_pkginfo_array, &ctx->dbi);

	foreach_array_item(arg, args) {
		r = load_index(ctx, apk_istream_from_url(*arg, apk_ctx_since(ac, 0)));
		if (r) {
			apk_err(out, "%s: %s", *arg, apk_error_str(r));
			goto err;
		}
		fprintf(stderr, "%s: %u packages\n", *arg, adb_ra_num(&ctx->pkgs));
	}

	adb_wo_obj(&ndx, ADBI_NDX_PACKAGES, &ctx->pkgs);
	adb_w_rootobj(&ndx);

	r = adb_c_create(apk_ostream_to_fd(STDOUT_FILENO), &ctx->dbi, trust);
err:
	adb_free(&ctx->dbi);

	return r;
}

static struct apk_applet apk_convndx = {
	.name = "convndx",
	.context_size = sizeof(struct conv_ctx),
	.optgroups = { &optgroup_global, &optgroup_signing },
	.main = conv_main,
};
APK_DEFINE_APPLET(apk_convndx);
