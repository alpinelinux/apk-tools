/* apk.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>

#include "apk_defines.h"
#include "apk_arch.h"
#include "apk_database.h"
#include "apk_applet.h"
#include "apk_blob.h"
#include "apk_print.h"
#include "apk_io.h"
#include "apk_fs.h"

char **apk_argv;

static void version(struct apk_out *out, const char *prefix)
{
	apk_out_fmt(out, prefix, "apk-tools " APK_VERSION ", compiled for " APK_DEFAULT_ARCH ".");
}

#define GLOBAL_OPTIONS(OPT) \
	OPT(OPT_GLOBAL_allow_untrusted,		"allow-untrusted") \
	OPT(OPT_GLOBAL_arch,			APK_OPT_ARG "arch") \
	OPT(OPT_GLOBAL_cache_dir,		APK_OPT_ARG "cache-dir") \
	OPT(OPT_GLOBAL_cache_max_age,		APK_OPT_ARG "cache-max-age") \
	OPT(OPT_GLOBAL_cache_packages,		APK_OPT_BOOL "cache-packages") \
	OPT(OPT_GLOBAL_cache_predownload,	APK_OPT_BOOL "cache-predownload") \
	OPT(OPT_GLOBAL_force,			APK_OPT_SH("f") "force") \
	OPT(OPT_GLOBAL_force_binary_stdout,	"force-binary-stdout") \
	OPT(OPT_GLOBAL_force_broken_world,	"force-broken-world") \
	OPT(OPT_GLOBAL_force_missing_repositories, "force-missing-repositories") \
	OPT(OPT_GLOBAL_force_no_chroot,		"force-no-chroot") \
	OPT(OPT_GLOBAL_force_non_repository,	"force-non-repository") \
	OPT(OPT_GLOBAL_force_old_apk,		"force-old-apk") \
	OPT(OPT_GLOBAL_force_overwrite,		"force-overwrite") \
	OPT(OPT_GLOBAL_force_refresh,		"force-refresh") \
	OPT(OPT_GLOBAL_help,			APK_OPT_SH("h") "help") \
	OPT(OPT_GLOBAL_interactive,		APK_OPT_SH("i") "interactive") \
	OPT(OPT_GLOBAL_keys_dir,		APK_OPT_ARG "keys-dir") \
	OPT(OPT_GLOBAL_legacy_info,		APK_OPT_BOOL "legacy-info") \
	OPT(OPT_GLOBAL_no_cache,		"no-cache") \
	OPT(OPT_GLOBAL_no_check_certificate,	"no-check-certificate") \
	OPT(OPT_GLOBAL_no_interactive,		"no-interactive") \
	OPT(OPT_GLOBAL_no_logfile,		"no-logfile") \
	OPT(OPT_GLOBAL_no_network,		"no-network") \
	OPT(OPT_GLOBAL_preserve_env,		"preserve-env") \
	OPT(OPT_GLOBAL_print_arch,		"print-arch") \
	OPT(OPT_GLOBAL_progress,		APK_OPT_BOOL "progress") \
	OPT(OPT_GLOBAL_progress_fd,		APK_OPT_ARG "progress-fd") \
	OPT(OPT_GLOBAL_purge,			"purge") \
	OPT(OPT_GLOBAL_quiet,			APK_OPT_SH("q") "quiet") \
	OPT(OPT_GLOBAL_repositories_file,	APK_OPT_ARG "repositories-file") \
	OPT(OPT_GLOBAL_repository,		APK_OPT_ARG APK_OPT_SH("X") "repository") \
	OPT(OPT_GLOBAL_repository_config,	APK_OPT_ARG "repository-config") \
	OPT(OPT_GLOBAL_root,			APK_OPT_ARG APK_OPT_SH("p") "root") \
	OPT(OPT_GLOBAL_timeout,			APK_OPT_ARG "timeout") \
	OPT(OPT_GLOBAL_update_cache,		APK_OPT_SH("U") "update-cache") \
	OPT(OPT_GLOBAL_uvol_manager,		APK_OPT_ARG "uvol-manager") \
	OPT(OPT_GLOBAL_verbose,			APK_OPT_SH("v") "verbose") \
	OPT(OPT_GLOBAL_version,			APK_OPT_SH("V") "version") \
	OPT(OPT_GLOBAL_wait,			APK_OPT_ARG "wait") \


APK_OPTIONS(optgroup_global_desc, GLOBAL_OPTIONS);

static int optgroup_global_parse(struct apk_ctx *ac, int opt, const char *optarg)
{
	struct apk_out *out = &ac->out;
	switch (opt) {
	case OPT_GLOBAL_help:
		return -ENOTSUP;
	case OPT_GLOBAL_root:
		ac->root = optarg;
		break;
	case OPT_GLOBAL_keys_dir:
		ac->keys_dir = optarg;
		break;
	case OPT_GLOBAL_repositories_file:
		ac->repositories_file = optarg;
		break;
	case OPT_GLOBAL_repository:
		apk_string_array_add(&ac->repository_list, (char*) optarg);
		break;
	case OPT_GLOBAL_repository_config:
		apk_string_array_add(&ac->repository_config_list, (char*) optarg);
		break;
	case OPT_GLOBAL_quiet:
		if (ac->out.verbosity) ac->out.verbosity--;
		break;
	case OPT_GLOBAL_verbose:
		ac->out.verbosity++;
		break;
	case OPT_GLOBAL_version:
		version(out, NULL);
		return -ESHUTDOWN;
	case OPT_GLOBAL_force:
		ac->force |= APK_FORCE_OVERWRITE | APK_FORCE_OLD_APK
			| APK_FORCE_BROKEN_WORLD | APK_FORCE_NON_REPOSITORY
			| APK_FORCE_BINARY_STDOUT;
		break;
	case OPT_GLOBAL_force_overwrite:
		ac->force |= APK_FORCE_OVERWRITE;
		break;
	case OPT_GLOBAL_force_old_apk:
		ac->force |= APK_FORCE_OLD_APK;
		break;
	case OPT_GLOBAL_force_broken_world:
		ac->force |= APK_FORCE_BROKEN_WORLD;
		break;
	case OPT_GLOBAL_force_refresh:
		ac->force |= APK_FORCE_REFRESH;
		break;
	case OPT_GLOBAL_force_no_chroot:
		ac->flags |= APK_NO_CHROOT;
		break;
	case OPT_GLOBAL_force_non_repository:
		ac->force |= APK_FORCE_NON_REPOSITORY;
		break;
	case OPT_GLOBAL_force_binary_stdout:
		ac->force |= APK_FORCE_BINARY_STDOUT;
		break;
	case OPT_GLOBAL_force_missing_repositories:
		ac->force |= APK_FORCE_MISSING_REPOSITORIES;
		break;
	case OPT_GLOBAL_interactive:
		ac->flags |= APK_INTERACTIVE;
		break;
	case OPT_GLOBAL_no_interactive:
		ac->flags &= ~APK_INTERACTIVE;
		break;
	case OPT_GLOBAL_preserve_env:
		ac->flags |= APK_PRESERVE_ENV;
		break;
	case OPT_GLOBAL_progress:
		ac->out.progress_disable = !APK_OPT_BOOL_VAL(optarg);
		break;
	case OPT_GLOBAL_progress_fd:
		ac->out.progress_fd = atoi(optarg);
		break;
	case OPT_GLOBAL_allow_untrusted:
		ac->flags |= APK_ALLOW_UNTRUSTED;
		break;
	case OPT_GLOBAL_purge:
		ac->flags |= APK_PURGE;
		break;
	case OPT_GLOBAL_wait:
		ac->lock_wait = atoi(optarg);
		break;
	case OPT_GLOBAL_no_logfile:
		ac->flags |= APK_NO_LOGFILE;
		break;
	case OPT_GLOBAL_no_network:
		ac->flags |= APK_NO_NETWORK;
		break;
	case OPT_GLOBAL_no_cache:
		ac->flags |= APK_NO_CACHE;
		break;
	case OPT_GLOBAL_no_check_certificate:
		apk_io_url_no_check_certificate();
		break;
	case OPT_GLOBAL_cache_dir:
		ac->cache_dir = optarg;
		break;
	case OPT_GLOBAL_update_cache:
		ac->cache_max_age = 0;
		break;
	case OPT_GLOBAL_uvol_manager:
		ac->uvol = optarg;
		break;
	case OPT_GLOBAL_cache_max_age:
		ac->cache_max_age = atoi(optarg) * 60;
		break;
	case OPT_GLOBAL_cache_packages:
		ac->cache_packages = APK_OPT_BOOL_VAL(optarg);
		break;
	case OPT_GLOBAL_cache_predownload:
		ac->cache_predownload = APK_OPT_BOOL_VAL(optarg);
		break;
	case OPT_GLOBAL_timeout:
		apk_io_url_set_timeout(atoi(optarg));
		break;
	case OPT_GLOBAL_arch:
		apk_string_array_add(&ac->arch_list, (char*) optarg);
		break;
	case OPT_GLOBAL_print_arch:
		puts(APK_DEFAULT_ARCH);
		return -ESHUTDOWN;
	case OPT_GLOBAL_legacy_info:
		ac->legacy_info = APK_OPT_BOOL_VAL(optarg);
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

#define COMMIT_OPTIONS(OPT) \
	OPT(OPT_COMMIT_clean_protected,		"clean-protected") \
	OPT(OPT_COMMIT_initramfs_diskless_boot,	"initramfs-diskless-boot") \
	OPT(OPT_COMMIT_no_commit_hooks,		"no-commit-hooks") \
	OPT(OPT_COMMIT_no_scripts,		"no-scripts") \
	OPT(OPT_COMMIT_overlay_from_stdin,	"overlay-from-stdin") \
	OPT(OPT_COMMIT_simulate,		APK_OPT_SH("s") "simulate")

APK_OPTIONS(optgroup_commit_desc, COMMIT_OPTIONS);

static int optgroup_commit_parse(struct apk_ctx *ac, int opt, const char *optarg)
{
	switch (opt) {
	case OPT_COMMIT_simulate:
		ac->flags |= APK_SIMULATE;
		break;
	case OPT_COMMIT_clean_protected:
		ac->flags |= APK_CLEAN_PROTECTED;
		break;
	case OPT_COMMIT_overlay_from_stdin:
		ac->flags |= APK_OVERLAY_FROM_STDIN;
		break;
	case OPT_COMMIT_no_scripts:
		ac->flags |= APK_NO_SCRIPTS;
		break;
	case OPT_COMMIT_no_commit_hooks:
		ac->flags |= APK_NO_COMMIT_HOOKS;
		break;
	case OPT_COMMIT_initramfs_diskless_boot:
		ac->open_flags |= APK_OPENF_CREATE;
		ac->flags |= APK_NO_COMMIT_HOOKS;
		ac->force |= APK_FORCE_OVERWRITE | APK_FORCE_OLD_APK
			|  APK_FORCE_BROKEN_WORLD | APK_FORCE_NON_REPOSITORY;
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

#define GENERATION_OPTIONS(OPT) \
	OPT(OPT_GENERATION_compression,	APK_OPT_ARG APK_OPT_SH("c") "compression") \
	OPT(OPT_GENERATION_sign_key,	APK_OPT_ARG "sign-key")

APK_OPTIONS(optgroup_generation_desc, GENERATION_OPTIONS);

int optgroup_generation_parse(struct apk_ctx *ac, int optch, const char *optarg)
{
	struct apk_trust *trust = &ac->trust;
	struct apk_out *out = &ac->out;
	struct apk_trust_key *key;

	switch (optch) {
	case OPT_GENERATION_compression:
		if (adb_parse_compression(optarg, &ac->compspec) != 0)
			return -EINVAL;
		break;
	case OPT_GENERATION_sign_key:
		key = apk_trust_load_key(AT_FDCWD, optarg, 1);
		if (IS_ERR(key)) {
			apk_err(out, "Failed to load signing key: %s: %s",
				optarg, apk_error_str(PTR_ERR(key)));
			return PTR_ERR(key);
		}
		list_add_tail(&key->key_node, &trust->private_key_list);
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

static int usage(struct apk_out *out, struct apk_applet *applet)
{
	version(out, NULL);
	apk_applet_help(applet, out);
	return 1;
}

static struct apk_applet *deduce_applet(int argc, char **argv)
{
	struct apk_applet *a;
	const char *prog;
	int i;

	prog = strrchr(argv[0], '/');
	if (prog == NULL)
		prog = argv[0];
	else
		prog++;

	if (strncmp(prog, "apk_", 4) == 0)
		return apk_applet_find(prog + 4);

	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-') continue;
		a = apk_applet_find(argv[i]);
		if (a) return a;
	}

	return NULL;
}

// Pack and unpack group and option id into one short (struct option.val & struct apk_options.short_option_val)
#define APK_OPTVAL_BOOL				0x8000
#define APK_OPTVAL_BOOL_TRUE			0x4000

#define APK_OPTVAL_PACK(group_id, option_id)	((group_id << 10) + option_id)
#define APK_OPTVAL_GROUPID(optval)		(((optval) >> 10) & 0xf)
#define APK_OPTVAL_OPTIONID(optval)		((optval) & 0x3ff)

void *apk_optval_arg(int val, void *optarg)
{
	if (val & APK_OPTVAL_BOOL_TRUE) return (void*) 1;
	if (val & APK_OPTVAL_BOOL) return (void*) 0;
	return optarg;
}

struct apk_options {
	struct option options[80];
	unsigned short short_option_val[64];
	char short_options[256];
	int num_opts, num_sopts;
};

static bool option_exists(struct apk_options *opts, const char *name)
{
	for (struct option *opt = opts->options; opt->name; opt++)
		if (strcmp(name, opt->name) == 0) return true;
	return false;
}

static void add_options(struct apk_options *opts, const char *desc, int group_id)
{
	unsigned short option_id = 0;
	int num_short;

	for (const char *d = desc; *d; d += strlen(d) + 1, option_id++) {
		struct option *opt = &opts->options[opts->num_opts];
		assert(opts->num_opts < ARRAY_SIZE(opts->options));

		opt->val = APK_OPTVAL_PACK(group_id, option_id);
		opt->flag = 0;
		opt->has_arg = no_argument;
		if ((unsigned char)*d == 0xaf) {
			opt->has_arg = required_argument;
			d++;
		}
		if ((unsigned char)*d == 0xab) {
			opt->val |= APK_OPTVAL_BOOL;
			d++;
		}
		num_short = 0;
		if ((unsigned char)*d >= 0xf0)
			num_short = *d++ & 0x0f;
		for (; num_short > 0; num_short--) {
			unsigned char ch = *(unsigned char *)d;
			assert(ch >= 64 && ch < 128);
			if (opts->short_option_val[ch-64]) continue;
			opts->short_option_val[ch-64] = opt->val;
			opts->short_options[opts->num_sopts++] = *d++;
			if (opt->has_arg != no_argument) opts->short_options[opts->num_sopts++] = ':';
			assert(opts->num_sopts < ARRAY_SIZE(opts->short_options));
		}
		if (option_exists(opts, d)) continue;
		opts->num_opts++;
		opt->name = d;
		if (opt->val & APK_OPTVAL_BOOL) {
			struct option *opt2 = &opts->options[opts->num_opts++];
			assert(opts->num_opts < ARRAY_SIZE(opts->options));
			*opt2 = *opt;
			opt2->val |= APK_OPTVAL_BOOL_TRUE;
			opt2->name += 3; // skip "no-"
		}
		assert(opt->val != '?');
	}
}

static void setup_automatic_flags(struct apk_ctx *ac)
{
	const char *tmp;

	if ((tmp = getenv("APK_PROGRESS_CHAR")) != NULL)
		ac->out.progress_char = tmp;
	else if ((tmp = getenv("LANG")) != NULL && strstr(tmp, "UTF-8") != NULL)
		ac->out.progress_char = "\u2588";

	if (!isatty(STDOUT_FILENO) || !isatty(STDERR_FILENO)) {
		ac->out.progress_disable = 1;
		return;
	}

	if ((tmp = getenv("TERM")) != NULL && strcmp(tmp, "dumb") == 0)
		ac->out.progress_disable = 1;

	if (!(ac->flags & APK_SIMULATE) && access("/etc/apk/interactive", F_OK) == 0)
		ac->flags |= APK_INTERACTIVE;
}

static int load_config(struct apk_ctx *ac, struct apk_options *opts)
{
	struct apk_out *out = &ac->out;
	struct apk_istream *is;
	apk_blob_t newline = APK_BLOB_STRLIT("\n"), comment = APK_BLOB_STRLIT("#");
	apk_blob_t space = APK_BLOB_STRLIT(" "), line, key, value;
	int r;

	is = apk_istream_from_file(AT_FDCWD, getenv("APK_CONFIG") ?: "/etc/apk/config");
	if (is == ERR_PTR(-ENOENT)) is = apk_istream_from_file(AT_FDCWD, "/lib/apk/config");
	if (IS_ERR(is)) return PTR_ERR(is);

	while (apk_istream_get_delim(is, newline, &line) == 0) {
		apk_blob_split(line, comment, &line, &value);
		if (!apk_blob_split(line, space, &key, &value)) {
			key = line;
			value = APK_BLOB_NULL;
		}
		key = apk_blob_trim_end(key, ' ');
		value = apk_blob_trim_end(value, ' ');
		if (key.len == 0) continue;

		r = -1;
		for (int i = 0; i < opts->num_opts; i++) {
			struct option *opt = &opts->options[i];
			char *str = NULL;
			if (strncmp(opt->name, key.ptr, key.len) != 0 || opt->name[key.len] != 0) continue;
			switch (opt->has_arg) {
			case no_argument:
				if (!APK_BLOB_IS_NULL(value)) r = -2;
				break;
			case required_argument:
				if (APK_BLOB_IS_NULL(value)) {
					r = -3;
					break;
				}
				str = apk_balloc_cstr(&ac->ba, value);
				break;
			}
			assert(APK_OPTVAL_GROUPID(opt->val) == 1);
			if (r == -1) r = optgroup_global_parse(ac, APK_OPTVAL_OPTIONID(opt->val), apk_optval_arg(opt->val, str));
			break;
		}
		switch (r) {
		case 0: break;
		case -1:
			apk_warn(out, "config: option '" BLOB_FMT "' unknown", BLOB_PRINTF(key));
			break;
		case -2:
			apk_warn(out, "config: option '" BLOB_FMT "' does not expect argument (got '" BLOB_FMT "')",
				BLOB_PRINTF(key), BLOB_PRINTF(value));
			break;
		case -3:
			apk_warn(out, "config: option '" BLOB_FMT "' expects an argument",
				BLOB_PRINTF(key));
			break;
		default: apk_warn(out, "config: setting option '" BLOB_FMT "' failed", BLOB_PRINTF(key)); break;
		}
	}
	return apk_istream_close(is);
}

static int parse_options(int argc, char **argv, struct apk_applet *applet, void *ctx, struct apk_ctx *ac)
{
	struct apk_out *out = &ac->out;
	struct apk_options opts;
	int r, p;

	memset(&opts, 0, sizeof opts);

	add_options(&opts, optgroup_global_desc, 1);
	setup_automatic_flags(ac);
	load_config(ac, &opts);

	if (applet) {
		if (applet->options_desc) add_options(&opts, applet->options_desc, 15);
		if (applet->optgroup_commit) add_options(&opts, optgroup_commit_desc, 2);
		if (applet->optgroup_query) add_options(&opts, optgroup_query_desc, 3);
		if (applet->optgroup_generation) add_options(&opts, optgroup_generation_desc, 4);
	}

	while ((p = getopt_long(argc, argv, opts.short_options, opts.options, NULL)) != -1) {
		if (p == '?') return 1;
		if (p >= 64 && p < 128) p = opts.short_option_val[p - 64];
		void *arg = apk_optval_arg(p, optarg);
		switch (APK_OPTVAL_GROUPID(p)) {
		case 1: r = optgroup_global_parse(ac, APK_OPTVAL_OPTIONID(p), arg); break;
		case 2: r = optgroup_commit_parse(ac, APK_OPTVAL_OPTIONID(p), arg); break;
		case 3: r = apk_query_parse_option(ac, APK_OPTVAL_OPTIONID(p), arg); break;
		case 4: r = optgroup_generation_parse(ac, APK_OPTVAL_OPTIONID(p), arg); break;
		case 15: r = applet->parse(ctx, ac, APK_OPTVAL_OPTIONID(p), arg); break;
		default: r = -ENOTSUP;
		}
		if (r == -ENOTSUP) return usage(out, applet);
		if (r == -EINVAL) {
			struct option *opt = opts.options;
			for (; opt->name; opt++)
				if (opt->val == p) break;
			assert(opt->val == p);
			assert(optarg);
			apk_err(out, "invalid argument for --%s: %s", opt->name, optarg);
			return 1;
		}
		if (r != 0) return r;
	}

	return 0;
}

static struct apk_ctx ctx;
static struct apk_database db;

static void on_sigint(int s)
{
	apk_db_close(&db);
	exit(128 + s);
}

static void on_sigwinch(int s)
{
	apk_out_reset(&ctx.out);
}

static void setup_terminal(void)
{
	static char buf[200];
	setvbuf(stderr, buf, _IOLBF, sizeof buf);
	signal(SIGWINCH, on_sigwinch);
	signal(SIGPIPE, SIG_IGN);
}

static int remove_empty_strings(int count, char **args)
{
	int i, j;
	for (i = j = 0; i < count; i++) {
		args[j] = args[i];
		if (args[j][0]) j++;
	}
	return j;
}

static void redirect_callback(int code, const char *url)
{
	apk_warn(&ctx.out, "Permanently redirected to %s", url);
}

int main(int argc, char **argv)
{
	void *applet_ctx = NULL;
	struct apk_out *out = &ctx.out;
	struct apk_string_array *args;
	struct apk_applet *applet;
	int r;

	apk_string_array_init(&args);

	apk_argv = malloc(sizeof(char*[argc+2]));
	memcpy(apk_argv, argv, sizeof(char*[argc]));
	apk_argv[argc] = NULL;
	apk_argv[argc+1] = NULL;

	apk_ctx_init(&ctx);
	umask(0);
	setup_terminal();

	applet = deduce_applet(argc, argv);
	if (applet != NULL) {
		ctx.query.ser = &apk_serializer_query;
		ctx.open_flags = applet->open_flags;
		if (applet->context_size) applet_ctx = calloc(1, applet->context_size);
		if (applet->parse) applet->parse(applet_ctx, &ctx, APK_OPTIONS_INIT, NULL);
	}

	apk_crypto_init();
	apk_io_url_init(&ctx.out);
	apk_io_url_set_timeout(60);
	apk_io_url_set_redirect_callback(redirect_callback);

	r = parse_options(argc, argv, applet, applet_ctx, &ctx);
	if (r != 0) goto err;

	if (applet == NULL) {
		if (argc > 1) {
			apk_err(out, "'%s' is not an apk command. See 'apk --help'.", argv[1]);
			return 1;
		}
		return usage(out, NULL);
	}

	argc -= optind;
	argv += optind;
	if (argc >= 1 && strcmp(argv[0], applet->name) == 0) {
		argc--;
		argv++;
	}
	if (applet->remove_empty_arguments)
		argc = remove_empty_strings(argc, argv);

	apk_db_init(&db, &ctx);
	signal(SIGINT, on_sigint);

	r = apk_ctx_prepare(&ctx);
	if (r != 0) goto err;

	apk_out_log_argv(&ctx.out, apk_argv);
	version(&ctx.out, APK_OUT_LOG_ONLY);

	if (ctx.open_flags) {
		r = apk_db_open(&db);
		if (r != 0) {
			apk_err(out, "Failed to open apk database: %s", apk_error_str(r));
			goto err;
		}
	}

	apk_string_array_resize(&args, 0, argc);
	for (r = 0; r < argc; r++) apk_string_array_add(&args, argv[r]);
	apk_io_url_set_redirect_callback(NULL);

	r = applet->main(applet_ctx, &ctx, args);
	signal(SIGINT, SIG_IGN);
	apk_db_close(&db);

err:
	if (r == -ESHUTDOWN) r = 0;
	if (applet_ctx) free(applet_ctx);

	apk_ctx_free(&ctx);
	apk_string_array_free(&args);
	free(apk_argv);

	if (r < 0) r = 250;
	if (r > 99) r = 99;
	return r;
}
