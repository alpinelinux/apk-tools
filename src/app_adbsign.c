#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "adb.h"
#include "apk_applet.h"
#include "apk_print.h"

struct sign_ctx {
	struct adb_xfrm xfrm;
	struct apk_database *db;
	int reset_signatures : 1;
	int signatures_written : 1;
};

#define ADBSIGN_OPTIONS(OPT) \
	OPT(OPT_ADBSIGN_reset_signatures,	"reset-signatures")

APK_OPT_APPLET(option_desc, ADBSIGN_OPTIONS);

static int option_parse_applet(void *pctx, struct apk_db_options *dbopts, int optch, const char *optarg)
{
	struct sign_ctx *ctx = (struct sign_ctx *) pctx;

	switch (optch) {
	case OPT_ADBSIGN_reset_signatures:
		ctx->reset_signatures = 1;
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

static const struct apk_option_group optgroup_applet = {
	.desc = option_desc,
	.parse = option_parse_applet,
};

static int update_signatures(struct adb_xfrm *xfrm, struct adb_block *blk, struct apk_istream *is)
{
	struct sign_ctx *ctx = container_of(xfrm, struct sign_ctx, xfrm);
	int r;

	switch (blk ? ADB_BLOCK_TYPE(blk) : -1) {
	case ADB_BLOCK_ADB:
		return adb_c_block_copy(xfrm->os, blk, is, &xfrm->vfy);
	case ADB_BLOCK_SIG:
		if (ctx->reset_signatures)
			break;
		return adb_c_block_copy(xfrm->os, blk, is, NULL);
	default:
		if (!ctx->signatures_written) {
			ctx->signatures_written = 1;
			r = adb_trust_write_signatures(&ctx->db->trust, &xfrm->db, &xfrm->vfy, xfrm->os);
			if (r) return r;
		}
		if (!blk) break;
		return adb_c_block_copy(xfrm->os, blk, is, NULL);
	}
	return 0;
}

static int adbsign_main(void *pctx, struct apk_database *db, struct apk_string_array *args)
{
	struct sign_ctx *ctx = pctx;
	char **arg;
	int r;

	ctx->db = db;
	foreach_array_item(arg, args) {
		ctx->xfrm.is = apk_istream_from_file(AT_FDCWD, *arg);
		ctx->xfrm.os = apk_ostream_to_file(AT_FDCWD, *arg, 0644);
		adb_c_xfrm(&ctx->xfrm, update_signatures);
		apk_istream_close(ctx->xfrm.is);
		r = apk_ostream_close(ctx->xfrm.os);
		if (r) apk_error("%s: %s", *arg, apk_error_str(r));
	}

	return 0;
}

static struct apk_applet apk_adbsign = {
	.name = "adbsign",
	.open_flags = APK_OPENF_READ | APK_OPENF_NO_STATE | APK_OPENF_NO_REPOS,
	.context_size = sizeof(struct sign_ctx),
	.optgroups = { &optgroup_global, &optgroup_signing, &optgroup_applet },
	.main = adbsign_main,
};

APK_DEFINE_APPLET(apk_adbsign);
