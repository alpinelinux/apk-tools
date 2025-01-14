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

#include <openssl/crypto.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include <fetch.h>

#include "apk_defines.h"
#include "apk_database.h"
#include "apk_applet.h"
#include "apk_blob.h"
#include "apk_print.h"
#include "apk_io.h"

#ifdef TEST_MODE
static const char *test_installed_db = NULL;
static const char *test_world = NULL;
static struct apk_string_array *test_repos;
#endif

char **apk_argv;

#ifdef TEST_MODE
time_t time(time_t *tloc)
{
	const time_t val = 1559567666;
	if (tloc) *tloc = val;
	return val;
}
#endif

static void version(void)
{
	printf("apk-tools " APK_VERSION ", compiled for " APK_DEFAULT_ARCH ".\n"
#ifdef TEST_MODE
		"TEST MODE BUILD. NOT FOR PRODUCTION USE.\n"
#endif
		);
}

static struct apk_repository_list *apk_repository_new(const char *url)
{
	struct apk_repository_list *r = calloc(1, sizeof(struct apk_repository_list));
	if (r) {
		r->url = url;
		list_init(&r->list);
	}
	return r;
}

#define GLOBAL_OPTIONS(OPT) \
	OPT(OPT_GLOBAL_allow_untrusted,		"allow-untrusted") \
	OPT(OPT_GLOBAL_arch,			APK_OPT_ARG "arch") \
	OPT(OPT_GLOBAL_cache_dir,		APK_OPT_ARG "cache-dir") \
	OPT(OPT_GLOBAL_cache_max_age,		APK_OPT_ARG "cache-max-age") \
	OPT(OPT_GLOBAL_force,			APK_OPT_SH("f") "force") \
	OPT(OPT_GLOBAL_force_binary_stdout,	"force-binary-stdout") \
	OPT(OPT_GLOBAL_force_broken_world,	"force-broken-world") \
	OPT(OPT_GLOBAL_force_missing_repositories, "force-missing-repositories") \
	OPT(OPT_GLOBAL_force_non_repository,	"force-non-repository") \
	OPT(OPT_GLOBAL_force_old_apk,		"force-old-apk") \
	OPT(OPT_GLOBAL_force_overwrite,		"force-overwrite") \
	OPT(OPT_GLOBAL_force_refresh,		"force-refresh") \
	OPT(OPT_GLOBAL_help,			APK_OPT_SH("h") "help") \
	OPT(OPT_GLOBAL_interactive,		APK_OPT_SH("i") "interactive") \
	OPT(OPT_GLOBAL_keys_dir,		APK_OPT_ARG "keys-dir") \
	OPT(OPT_GLOBAL_no_cache,		"no-cache") \
	OPT(OPT_GLOBAL_no_check_certificate,	"no-check-certificate") \
	OPT(OPT_GLOBAL_no_interactive,		"no-interactive") \
	OPT(OPT_GLOBAL_no_network,		"no-network") \
	OPT(OPT_GLOBAL_no_progress,		"no-progress") \
	OPT(OPT_GLOBAL_print_arch,		"print-arch") \
	OPT(OPT_GLOBAL_progress,		"progress") \
	OPT(OPT_GLOBAL_progress_fd,		APK_OPT_ARG "progress-fd") \
	OPT(OPT_GLOBAL_purge,			"purge") \
	OPT(OPT_GLOBAL_quiet,			APK_OPT_SH("q") "quiet") \
	OPT(OPT_GLOBAL_repositories_file,	APK_OPT_ARG "repositories-file") \
	OPT(OPT_GLOBAL_repository,		APK_OPT_ARG APK_OPT_SH("X") "repository") \
	OPT(OPT_GLOBAL_root,			APK_OPT_ARG APK_OPT_SH("p") "root") \
	OPT(OPT_GLOBAL_timeout,			APK_OPT_ARG "timeout") \
	OPT(OPT_GLOBAL_update_cache,		APK_OPT_SH("U") "update-cache") \
	OPT(OPT_GLOBAL_verbose,			APK_OPT_SH("v") "verbose") \
	OPT(OPT_GLOBAL_version,			APK_OPT_SH("V") "version") \
	OPT(OPT_GLOBAL_wait,			APK_OPT_ARG "wait") \

#define TEST_OPTIONS(OPT) \
	OPT(OPT_GLOBAL_test_instdb,		APK_OPT_ARG "test-instdb") \
	OPT(OPT_GLOBAL_test_repo,		APK_OPT_ARG "test-repo") \
	OPT(OPT_GLOBAL_test_world,		APK_OPT_ARG "test-world")


#ifdef TEST_MODE
APK_OPT_GROUP2(optiondesc_global, "Global", GLOBAL_OPTIONS, TEST_OPTIONS);
#else
APK_OPT_GROUP(optiondesc_global, "Global", GLOBAL_OPTIONS);
#endif

static int option_parse_global(void *ctx, struct apk_db_options *dbopts, int opt, const char *optarg)
{
	struct apk_repository_list *repo;

	switch (opt) {
	case OPT_GLOBAL_help:
		return -EINVAL;
	case OPT_GLOBAL_root:
		dbopts->root = optarg;
		break;
	case OPT_GLOBAL_keys_dir:
		dbopts->keys_dir = optarg;
		break;
	case OPT_GLOBAL_repositories_file:
		dbopts->repositories_file = optarg;
		break;
	case OPT_GLOBAL_repository:
		repo = apk_repository_new(optarg);
		if (repo) list_add(&repo->list, &dbopts->repository_list);
		break;
	case OPT_GLOBAL_quiet:
		apk_verbosity--;
		break;
	case OPT_GLOBAL_verbose:
		apk_verbosity++;
		break;
	case OPT_GLOBAL_version:
		version();
		return -ESHUTDOWN;
	case OPT_GLOBAL_force:
		apk_force |= APK_FORCE_OVERWRITE | APK_FORCE_OLD_APK
			  |  APK_FORCE_BROKEN_WORLD | APK_FORCE_NON_REPOSITORY
			  |  APK_FORCE_BINARY_STDOUT;
		break;
	case OPT_GLOBAL_force_overwrite:
		apk_force |= APK_FORCE_OVERWRITE;
		break;
	case OPT_GLOBAL_force_old_apk:
		apk_force |= APK_FORCE_OLD_APK;
		break;
	case OPT_GLOBAL_force_broken_world:
		apk_force |= APK_FORCE_BROKEN_WORLD;
		break;
	case OPT_GLOBAL_force_refresh:
		apk_force |= APK_FORCE_REFRESH;
		break;
	case OPT_GLOBAL_force_non_repository:
		apk_force |= APK_FORCE_NON_REPOSITORY;
		break;
	case OPT_GLOBAL_force_binary_stdout:
		apk_force |= APK_FORCE_BINARY_STDOUT;
		break;
	case OPT_GLOBAL_force_missing_repositories:
		apk_force |= APK_FORCE_MISSING_REPOSITORIES;
		break;
	case OPT_GLOBAL_interactive:
		apk_flags |= APK_INTERACTIVE;
		break;
	case OPT_GLOBAL_no_interactive:
		apk_flags &= ~APK_INTERACTIVE;
		break;
	case OPT_GLOBAL_progress:
		apk_flags |= APK_PROGRESS;
		break;
	case OPT_GLOBAL_no_progress:
		apk_flags &= ~APK_PROGRESS;
		break;
	case OPT_GLOBAL_progress_fd:
		apk_progress_fd = atoi(optarg);
		break;
	case OPT_GLOBAL_allow_untrusted:
		apk_flags |= APK_ALLOW_UNTRUSTED;
		break;
	case OPT_GLOBAL_purge:
		apk_flags |= APK_PURGE;
		break;
	case OPT_GLOBAL_wait:
		dbopts->lock_wait = atoi(optarg);
		break;
	case OPT_GLOBAL_no_network:
		apk_flags |= APK_NO_NETWORK;
		break;
	case OPT_GLOBAL_no_cache:
		apk_flags |= APK_NO_CACHE;
		break;
	case OPT_GLOBAL_no_check_certificate:
		fetch_no_check_certificate();
		break;
	case OPT_GLOBAL_cache_dir:
		dbopts->cache_dir = optarg;
		break;
	case OPT_GLOBAL_update_cache:
		dbopts->cache_max_age = -1;
		break;
	case OPT_GLOBAL_cache_max_age:
		dbopts->cache_max_age = atoi(optarg) * 60;
		if (!dbopts->cache_max_age) dbopts->cache_max_age = -1;
		break;
	case OPT_GLOBAL_timeout:
		fetchTimeout = atoi(optarg);
		break;
	case OPT_GLOBAL_arch:
		dbopts->arch = optarg;
		break;
	case OPT_GLOBAL_print_arch:
		puts(APK_DEFAULT_ARCH);
		return -ESHUTDOWN;
#ifdef TEST_MODE
	case OPT_GLOBAL_test_repo:
		*apk_string_array_add(&test_repos) = (char*) optarg;
		break;
	case OPT_GLOBAL_test_instdb:
		test_installed_db = optarg;
		break;
	case OPT_GLOBAL_test_world:
		test_world = optarg;
		break;
#endif
	default:
		return -ENOTSUP;
	}
	return 0;
}

const struct apk_option_group optgroup_global = {
	.desc = optiondesc_global,
	.parse = option_parse_global,
};

#define COMMIT_OPTIONS(OPT) \
	OPT(OPT_COMMIT_clean_protected,		"clean-protected") \
	OPT(OPT_COMMIT_initramfs_diskless_boot,	"initramfs-diskless-boot") \
	OPT(OPT_COMMIT_no_commit_hooks,		"no-commit-hooks") \
	OPT(OPT_COMMIT_no_scripts,		"no-scripts") \
	OPT(OPT_COMMIT_overlay_from_stdin,	"overlay-from-stdin") \
	OPT(OPT_COMMIT_simulate,		APK_OPT_SH("s") "simulate")

APK_OPT_GROUP(optiondesc_commit, "Commit", COMMIT_OPTIONS);

static int option_parse_commit(void *ctx, struct apk_db_options *dbopts, int opt, const char *optarg)
{
	switch (opt) {
	case OPT_COMMIT_simulate:
		apk_flags |= APK_SIMULATE;
		break;
	case OPT_COMMIT_clean_protected:
		apk_flags |= APK_CLEAN_PROTECTED;
		break;
	case OPT_COMMIT_overlay_from_stdin:
		apk_flags |= APK_OVERLAY_FROM_STDIN;
		break;
	case OPT_COMMIT_no_scripts:
		apk_flags |= APK_NO_SCRIPTS;
		break;
	case OPT_COMMIT_no_commit_hooks:
		apk_flags |= APK_NO_COMMIT_HOOKS;
		break;
	case OPT_COMMIT_initramfs_diskless_boot:
		dbopts->open_flags |= APK_OPENF_CREATE;
		apk_flags |= APK_NO_COMMIT_HOOKS;
		apk_force |= APK_FORCE_OVERWRITE | APK_FORCE_OLD_APK
			  |  APK_FORCE_BROKEN_WORLD | APK_FORCE_NON_REPOSITORY;
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

const struct apk_option_group optgroup_commit = {
	.desc = optiondesc_commit,
	.parse = option_parse_commit,
};

#define SOURCE_OPTIONS(OPT) \
	OPT(OPT_SOURCE_from,		APK_OPT_ARG "from")

APK_OPT_GROUP(optiondesc_source, "Source", SOURCE_OPTIONS);

static int option_parse_source(void *ctx, struct apk_db_options *dbopts, int opt, const char *optarg)
{
	const unsigned long all_flags = APK_OPENF_NO_SYS_REPOS | APK_OPENF_NO_INSTALLED_REPO | APK_OPENF_NO_INSTALLED;
	unsigned long flags;

	switch (opt) {
	case OPT_SOURCE_from:
		if (strcmp(optarg, "none") == 0) {
			flags = APK_OPENF_NO_SYS_REPOS | APK_OPENF_NO_INSTALLED_REPO | APK_OPENF_NO_INSTALLED;
		} else if (strcmp(optarg, "repositories") == 0) {
			flags = APK_OPENF_NO_INSTALLED_REPO | APK_OPENF_NO_INSTALLED;
		} else if (strcmp(optarg, "installed") == 0) {
			flags = APK_OPENF_NO_SYS_REPOS;
		} else if (strcmp(optarg, "system") == 0) {
			flags = 0;
		} else
			return -ENOTSUP;

		dbopts->open_flags &= ~all_flags;
		dbopts->open_flags |= flags;
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

const struct apk_option_group optgroup_source = {
	.desc = optiondesc_source,
	.parse = option_parse_source,
};

static int usage(struct apk_applet *applet)
{
	version();
	apk_applet_help(applet);
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

static int parse_options(int argc, char **argv, struct apk_applet *applet, void *ctx, struct apk_db_options *dbopts)
{
	const struct apk_option_group *default_optgroups[] = { &optgroup_global, NULL };
	const struct apk_option_group *og, **optgroups = default_optgroups;
	struct option all_options[80], *opt;
	char short_options[256], *sopt;
	unsigned short short_option_val[64];
	int r, p, help_requested = 0, num_short;

	memset(short_option_val, 0, sizeof short_option_val);

	if (applet && applet->optgroups[0]) optgroups = applet->optgroups;

	for (p = 0, opt = &all_options[0], sopt = short_options; (og = optgroups[p]) != 0; p++) {
		assert(opt < &all_options[ARRAY_SIZE(all_options)]);
		assert(sopt < &short_options[sizeof short_options]);
		const char *d = og->desc + strlen(og->desc) + 1;
		for (r = 0; *d; r++) {
			opt->val = (p << 10) + r;
			opt->flag = 0;
			opt->has_arg = no_argument;
			if ((unsigned char)*d == 0xaf) {
				opt->has_arg = required_argument;
				d++;
			}
			num_short = 0;
			if ((unsigned char)*d >= 0xf0)
				num_short = *d++ & 0x0f;
			for (; num_short > 0; num_short--) {
				unsigned char ch = *(unsigned char *)d;
				assert(ch >= 64 && ch < 128);
				short_option_val[ch-64] = opt->val;
				*sopt++ = *d++;
				if (opt->has_arg != no_argument)
					*sopt++ = ':';
			}
			opt->name = d;
			opt++;
			d += strlen(d) + 1;
		}
	}
	opt->name = 0;
	*sopt = 0;

	r = 0;
	while ((p = getopt_long(argc, argv, short_options, all_options, NULL)) != -1) {
		if (p >= 64 && p < 128) p = short_option_val[p - 64];
		og = optgroups[p >> 10];
		r = og->parse(ctx, dbopts, p & 0x3ff, optarg);
		if (r == 0) continue;
		if (r == -EINVAL) {
			help_requested = 1;
			continue;
		}
		if (r != -ENOTSUP) return r;
	}

	if (help_requested || r == -ENOTSUP)
		return usage(applet);

	return 0;
}

static void fini_openssl(void)
{
	EVP_cleanup();
#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif
	CRYPTO_cleanup_all_ex_data();
}

static void init_openssl(void)
{
	atexit(fini_openssl);
	OpenSSL_add_all_algorithms();
#ifndef OPENSSL_NO_ENGINE
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();
#endif
}

static void on_sigwinch(int s)
{
	apk_reset_screen_width();
}

static void setup_terminal(void)
{
	signal(SIGWINCH, on_sigwinch);
	signal(SIGPIPE, SIG_IGN);
}

static void setup_automatic_flags(void)
{
	const char *tmp;

	if (!isatty(STDOUT_FILENO) || !isatty(STDERR_FILENO) ||
	    !isatty(STDIN_FILENO))
		return;

	/* Enable progress bar by default, except on dumb terminals. */
	if (!(tmp = getenv("TERM")) || strcmp(tmp, "dumb") != 0)
		apk_flags |= APK_PROGRESS;

	if (!(apk_flags & APK_SIMULATE) &&
	    access("/etc/apk/interactive", F_OK) == 0)
		apk_flags |= APK_INTERACTIVE;
}

static struct apk_database db;

static void on_sigint(int s)
{
	apk_db_close(&db);
	exit(128 + s);
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

static void fetch_redirect(int code, const struct url *cur, const struct url *next)
{
	char *url;

	switch (code) {
	case 301: // Moved Permanently
	case 308: // Permanent Redirect
		url = fetchStringifyURL(next);
		apk_warning("Permanently redirected to %s", url);
		free(url);
		break;
	}
}

int main(int argc, char **argv)
{
	void *ctx = NULL;
	struct apk_db_options dbopts;
	struct apk_string_array *args;
	struct apk_applet *applet;
	int r;

	apk_string_array_init(&args);
#ifdef TEST_MODE
	apk_string_array_init(&test_repos);
#endif

	apk_argv = malloc(sizeof(char*[argc+2]));
	memcpy(apk_argv, argv, sizeof(char*[argc]));
	apk_argv[argc] = NULL;
	apk_argv[argc+1] = NULL;

	memset(&dbopts, 0, sizeof(dbopts));
	list_init(&dbopts.repository_list);
	umask(0);
	setup_terminal();

	applet = deduce_applet(argc, argv);
	if (applet != NULL) {
		if (applet->context_size != 0)
			ctx = calloc(1, applet->context_size);
		dbopts.open_flags = applet->open_flags;
		if (applet->update_cache) dbopts.cache_max_age = 0;
	}

	init_openssl();
	setup_automatic_flags();
	fetchTimeout = 60;
	fetchRedirectMethod = fetch_redirect;
	fetchConnectionCacheInit(32, 4);

	r = parse_options(argc, argv, applet, ctx, &dbopts);
	if (r != 0) goto err;

	if (applet == NULL) {
		if (argc > 1) {
			apk_error("'%s' is not an apk command. See 'apk --help'.", argv[1]);
			return 1;
		}
		return usage(NULL);
	}

	argc -= optind;
	argv += optind;
	if (argc >= 1 && strcmp(argv[0], applet->name) == 0) {
		argc--;
		argv++;
	}
	if (applet->remove_empty_arguments)
		argc = remove_empty_strings(argc, argv);

	apk_db_init(&db);
	signal(SIGINT, on_sigint);

#ifdef TEST_MODE
	dbopts.open_flags &= ~(APK_OPENF_WRITE | APK_OPENF_CACHE_WRITE | APK_OPENF_CREATE);
	dbopts.open_flags |= APK_OPENF_READ | APK_OPENF_NO_STATE | APK_OPENF_NO_REPOS;
	apk_flags |= APK_SIMULATE;
	apk_flags &= ~APK_INTERACTIVE;
#endif
	r = apk_db_open(&db, &dbopts);
	if (r != 0) {
		apk_error("Failed to open apk database: %s",
			  apk_error_str(r));
		goto err;
	}

#ifdef TEST_MODE
	if (test_world != NULL) {
		apk_blob_t b = APK_BLOB_STR(test_world);
		apk_blob_pull_deps(&b, &db, &db.world);
	}
	if (test_installed_db != NULL) {
		apk_db_index_read(&db, apk_istream_from_file(AT_FDCWD, test_installed_db), -1);
	}
	for (int i = 0; i < test_repos->num; i++) {
		apk_blob_t spec = APK_BLOB_STR(test_repos->item[i]), name, tag;
		int repo_tag = 0, repo = APK_REPOSITORY_FIRST_CONFIGURED + i;

		if (spec.ptr[0] == '!') {
			/* cache's installed repository */
			spec.ptr++;
			spec.len--;
			repo = -2;
		}

		if (apk_blob_split(spec, APK_BLOB_STR(":"), &tag, &name)) {
			repo_tag = apk_db_get_tag_id(&db, tag);
		} else {
			name = spec;
		}

		r = apk_db_index_read(&db, apk_istream_from_file(AT_FDCWD, name.ptr), repo);
		if (r != 0) {
			apk_error("Failed to open test repository " BLOB_FMT " : %s", BLOB_PRINTF(name), apk_error_str(r));
			goto err;
		}

		if (repo != -2) {
			if (!(apk_flags & APK_NO_NETWORK))
				db.available_repos |= BIT(repo);
			db.repo_tags[repo_tag].allowed_repos |= BIT(repo);
		}
	}
#endif

	apk_string_array_resize(&args, argc);
	memcpy(args->item, argv, argc * sizeof(*argv));
	fetchRedirectMethod = NULL;

	r = applet->main(ctx, &db, args);
	signal(SIGINT, SIG_IGN);
	apk_db_close(&db);

#ifdef TEST_MODE
	/* in test mode, we need to always exit 0 since xargs dies otherwise */
	r = 0;
#endif

err:
	if (r == -ESHUTDOWN) r = 0;
	if (ctx) free(ctx);

	fetchConnectionCacheClose();
	apk_string_array_free(&args);
	free(apk_argv);

	if (r < 0) r = 250;
	if (r > 99) r = 99;
	return r;
}
