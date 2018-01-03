/* apk.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
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

static const struct apk_option_group *default_optgroups[] = { &optgroup_global, NULL };
static struct list_head apk_applet_list;
#define foreach_applet(iter) list_for_each_entry(iter, &apk_applet_list, node)

#ifdef TEST_MODE
static const char *test_installed_db = NULL;
static const char *test_world = NULL;
static struct apk_string_array *test_repos;
#endif

char **apk_argv;

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

static int option_parse_global(void *ctx, struct apk_db_options *dbopts, int optch, const char *optarg)
{
	struct apk_repository_list *repo;

	switch (optch) {
	case 'h': return -EINVAL;
	case 'p':
		dbopts->root = optarg;
		break;
	case 0x107:
		dbopts->keys_dir = optarg;
		break;
	case 0x108:
		dbopts->repositories_file = optarg;
		break;
	case 'X':
		repo = apk_repository_new(optarg);
		if (repo) list_add(&repo->list, &dbopts->repository_list);
		break;
	case 'q':
		apk_verbosity--;
		break;
	case 'v':
		apk_verbosity++;
		break;
	case 'V':
		version();
		return -ESHUTDOWN;
	case 'f':
		apk_flags |= APK_FORCE;
		break;
	case 'i':
		apk_flags |= APK_INTERACTIVE;
		break;
	case 'U':
		apk_flags |= APK_UPDATE_CACHE;
		break;
	case 0x101:
		apk_flags |= APK_PROGRESS;
		break;
	case 0x104:
		apk_flags |= APK_SIMULATE;
		break;
	case 0x110:
		apk_flags &= ~APK_PROGRESS;
		break;
	case 0x10f:
		apk_progress_fd = atoi(optarg);
		break;
	case 0x103:
		apk_flags |= APK_ALLOW_UNTRUSTED;
		break;
	case 0x106:
		apk_flags |= APK_PURGE;
		break;
	case 0x105:
		dbopts->lock_wait = atoi(optarg);
		break;
	case 0x109:
		apk_flags |= APK_NO_NETWORK;
		break;
	case 0x115:
		apk_flags |= APK_NO_CACHE;
		break;
	case 0x116:
		dbopts->cache_dir = optarg;
		break;
	case 0x112:
		dbopts->arch = optarg;
		break;
	case 0x114:
		puts(APK_DEFAULT_ARCH);
		return -ESHUTDOWN;
#ifdef TEST_MODE
	case 0x200:
		*apk_string_array_add(&test_repos) = (char*) optarg;
		break;
	case 0x201:
		test_installed_db = optarg;
		break;
	case 0x202:
		test_world = optarg;
		break;
#endif
	default:
		return -ENOTSUP;
	}
	return 0;
}

static const struct apk_option options_global[] = {
	{ 'h', "help",		"Show generic help or applet specific help" },
	{ 'p', "root",		"Install packages to DIR",
				required_argument, "DIR" },
	{ 'X', "repository",	"Use packages from REPO",
				required_argument, "REPO" },
	{ 'q', "quiet",		"Print less information" },
	{ 'v', "verbose",	"Print more information (can be doubled)" },
	{ 'i', "interactive",	"Ask confirmation for certain operations" },
	{ 'V', "version",	"Print program version and exit" },
	{ 'f', "force",		"Do what was asked even if it looks dangerous" },
	{ 'U', "update-cache",	"Update the repository cache" },
	{ 0x101, "progress",	"Show a progress bar" },
	{ 0x10f, "progress-fd",	"Write progress to fd", required_argument, "FD" },
	{ 0x110, "no-progress",	"Disable progress bar even for TTYs" },
	{ 0x106, "purge",	"Delete also modified configuration files (pkg removal) "
				"and uninstalled packages from cache (cache clean)" },
	{ 0x103, "allow-untrusted", "Install packages with untrusted signature or no signature" },
	{ 0x105, "wait",	"Wait for TIME seconds to get an exclusive "
				"repository lock before failing",
				required_argument, "TIME" },
	{ 0x107, "keys-dir",	"Override directory of trusted keys",
				required_argument, "KEYSDIR" },
	{ 0x108, "repositories-file", "Override repositories file",
				required_argument, "REPOFILE" },
	{ 0x109, "no-network",	"Do not use network (cache is still used)" },
	{ 0x115, "no-cache",	"Read uncached index from network" },
	{ 0x116, "cache-dir",	"Override cache directory",
				required_argument, "CACHEDIR" },
	{ 0x112, "arch",	"Use architecture with --root",
				required_argument, "ARCH" },
	{ 0x114, "print-arch",	"Print default arch and exit" },
#ifdef TEST_MODE
	{ 0x200, "test-repo",	"Repository", required_argument, "REPO" },
	{ 0x201, "test-instdb",	"Installed db", required_argument, "INSTALLED" },
	{ 0x202, "test-world",	"World", required_argument, "WORLD DEPS" },
#endif
};

const struct apk_option_group optgroup_global = {
	.name = "Global",
	.options = options_global,
	.num_options = ARRAY_SIZE(options_global),
	.parse = option_parse_global,
};

static int option_parse_commit(void *ctx, struct apk_db_options *dbopts, int optch, const char *optarg)
{
	switch (optch) {
	case 's':
		apk_flags |= APK_SIMULATE;
		break;
	case 0x102:
		apk_flags |= APK_CLEAN_PROTECTED;
		break;
	case 0x111:
		apk_flags |= APK_OVERLAY_FROM_STDIN;
		break;
	case 0x113:
		apk_flags |= APK_NO_SCRIPTS;
		break;
	case 0x117:
		apk_flags |= APK_NO_COMMIT_HOOKS;
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

static const struct apk_option options_commit[] = {
	{ 's', "simulate",		"Show what would be done without actually doing it" },
	{ 0x102, "clean-protected",	"Do not create .apk-new files in configuration dirs" },
	{ 0x111, "overlay-from-stdin",	"Read list of overlay files from stdin" },
	{ 0x113, "no-scripts",		"Do not execute any scripts" },
	{ 0x117, "no-commit-hooks",	"Skip pre/post hook scripts (but not other scripts)" },
};

const struct apk_option_group optgroup_commit = {
	.name = "Commit",
	.options = options_commit,
	.num_options = ARRAY_SIZE(options_commit),
	.parse = option_parse_commit,
};

static int format_option(char *buf, size_t len, const struct apk_option *o,
			 const char *separator)
{
	int i = 0;

	if (o->val <= 0xff && isalnum(o->val)) {
		i += snprintf(&buf[i], len - i, "-%c", o->val);
		if (o->name != NULL)
			i += snprintf(&buf[i], len - i, "%s", separator);
	}
	if (o->name != NULL)
		i += snprintf(&buf[i], len - i, "--%s", o->name);
	if (o->arg_name != NULL)
		i += snprintf(&buf[i], len - i, " %s", o->arg_name);

	return i;
}

static void print_usage(const char *cmd, const char *args, const struct apk_option_group **optgroups)
{
	struct apk_indent indent = { .indent = 11 };
	const struct apk_option *opts;
	char word[128];
	int g, i, j;

	indent.x = printf("\nusage: apk %s", cmd) - 1;
	for (g = 0; optgroups[g]; g++) {
		opts = optgroups[g]->options;
		for (i = 0; i < optgroups[g]->num_options; i++) {
			if (!opts[i].name) continue;
			j = 0;
			word[j++] = '[';
			j += format_option(&word[j], sizeof(word) - j, &opts[i], "|");
			word[j++] = ']';
			apk_print_indented(&indent, APK_BLOB_PTR_LEN(word, j));
		}
	}
	if (args != NULL)
		apk_print_indented(&indent, APK_BLOB_STR(args));
	printf("\n");
}

static void print_options(int num_opts, const struct apk_option *opts)
{
	struct apk_indent indent = { .indent = 26 };
	char word[128];
	int i;

	for (i = 0; i < num_opts; i++) {
		format_option(word, sizeof(word), &opts[i], ", ");
		indent.x = printf("  %-*s", indent.indent - 3, word);
		apk_print_indented_words(&indent, opts[i].help);
		printf("\n");
	}
}

static int usage(struct apk_applet *applet)
{
	const struct apk_option_group **optgroups = default_optgroups;
	int i;

	version();
	if (applet == NULL) {
		struct apk_applet *a;

		print_usage("COMMAND", "[ARGS]...", default_optgroups);

		printf("\nThe following commands are available:\n");
		foreach_applet(a) {
			struct apk_indent indent = { .indent = 12 };
			indent.x = printf("  %-*s", indent.indent - 3, a->name);
			apk_print_indented_words(&indent, a->help);
			printf("\n");
		}
	} else {
		struct apk_indent indent = { .indent = 2 };

		if (applet->optgroups[0]) optgroups = applet->optgroups;
		print_usage(applet->name, applet->arguments, applet->optgroups);
		printf("\nDescription:\n");
		apk_print_indented_words(&indent, applet->help);
		printf("\n");
	}

	for (i = 0; optgroups[i]; i++) {
		printf("\n%s options:\n", optgroups[i]->name);
		print_options(optgroups[i]->num_options, optgroups[i]->options);
	}

	printf("\nThis apk has coffee making abilities.\n");

	return 1;
}

static struct apk_applet *find_applet(const char *name)
{
	struct apk_applet *a;

	foreach_applet(a) {
		if (strcmp(name, a->name) == 0)
			return a;
	}

	return NULL;
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
		return find_applet(prog + 4);

	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-')
			continue;

		a = find_applet(argv[i]);
		if (a != NULL)
			return a;
	}

	return NULL;
}

static void merge_options(struct option *opts, const struct apk_option *ao, int num)
{
	int i;

	for (i = 0; i < num; i++, opts++, ao++) {
		opts->name = ao->name ?: "";
		opts->has_arg = ao->has_arg;
		opts->flag = NULL;
		opts->val = ao->val;
	}
	opts->name = NULL;
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
	if (!isatty(STDOUT_FILENO) || !isatty(STDERR_FILENO) ||
	    !isatty(STDIN_FILENO))
		return;

	apk_flags |= APK_PROGRESS;
	if (!(apk_flags & APK_SIMULATE) &&
	    access("/etc/apk/interactive", F_OK) == 0)
		apk_flags |= APK_INTERACTIVE;
}

void apk_applet_register(struct apk_applet *applet)
{
	list_init(&applet->node);
	list_add_tail(&applet->node, &apk_applet_list);
}

static void apk_applet_register_builtin(void)
{
	extern apk_init_func_t __start_initapplets[], __stop_initapplets[];
	apk_init_func_t *p;

	list_init(&apk_applet_list);
	for (p = __start_initapplets; p < __stop_initapplets; p++)
		(*p)();
}

static struct apk_database db;

static void on_sigint(int s)
{
	apk_db_close(&db);
	exit(128 + s);
}

int main(int argc, char **argv)
{
	struct apk_applet *applet;
	char short_options[256], *sopt;
	struct option *opt, *all_options;
	int i, p, r, num_options;
	void *ctx = NULL;
	struct apk_db_options dbopts;
	const struct apk_option_group **optgroups = default_optgroups;
	struct apk_string_array *args;

#ifdef TEST_MODE
	apk_string_array_init(&test_repos);
#endif
	apk_applet_register_builtin();

	apk_argv = malloc(sizeof(char*[argc+2]));
	memcpy(apk_argv, argv, sizeof(char*[argc]));
	apk_argv[argc] = NULL;
	apk_argv[argc+1] = NULL;

	memset(&dbopts, 0, sizeof(dbopts));
	list_init(&dbopts.repository_list);
	apk_atom_init();
	umask(0);
	setup_terminal();

	applet = deduce_applet(argc, argv);
	if (applet && applet->optgroups[0]) optgroups = applet->optgroups;

	for (i = 0, num_options = 0; optgroups[i]; i++)
		num_options += optgroups[i]->num_options;
	all_options = alloca(sizeof(struct option) * num_options);
	for (i = r = 0; optgroups[i]; r += optgroups[i]->num_options, i++)
		merge_options(&all_options[r], optgroups[i]->options, optgroups[i]->num_options);
	if (applet != NULL) {
		if (applet->context_size != 0)
			ctx = calloc(1, applet->context_size);
		dbopts.open_flags = applet->open_flags;
		apk_flags |= applet->forced_flags;
	}
	for (opt = all_options, sopt = short_options; opt->name != NULL; opt++) {
		if (opt->flag == NULL &&
		    opt->val <= 0xff && isalnum(opt->val)) {
			*(sopt++) = opt->val;
			if (opt->has_arg != no_argument)
				*(sopt++) = ':';
		}
	}

	init_openssl();
	setup_automatic_flags();
	fetchConnectionCacheInit(16, 1);

	while ((p = getopt_long(argc, argv, short_options, all_options, NULL)) != -1) {
		for (i = 0; optgroups[i]; i++) {
			r = optgroups[i]->parse(ctx, &dbopts, p, optarg);
			if (r == 0) break;
			if (r != -ENOTSUP) goto err_and_usage;
		}
	}

	if (applet == NULL) {
		r = usage(NULL);
		goto err;
	}

	argc -= optind;
	argv += optind;
	if (argc >= 1 && strcmp(argv[0], applet->name) == 0) {
		argc--;
		argv++;
	}

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
		struct apk_bstream *bs = apk_bstream_from_file(AT_FDCWD, test_installed_db);
		if (!IS_ERR_OR_NULL(bs)) {
			apk_db_index_read(&db, bs, -1);
			apk_bstream_close(bs, NULL);
		}
	}
	for (i = 0; i < test_repos->num; i++) {
		struct apk_bstream *bs;
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

		bs = apk_bstream_from_file(AT_FDCWD, name.ptr);
		if (IS_ERR_OR_NULL(bs)) {
			apk_error("Failed to open repository: " BLOB_FMT, BLOB_PRINTF(name));
			goto err;
		}

		apk_db_index_read(&db, bs, repo);
		apk_bstream_close(bs, NULL);
		if (repo != -2) {
			if (!(apk_flags & APK_NO_NETWORK))
				db.available_repos |= BIT(repo);
			db.repo_tags[repo_tag].allowed_repos |= BIT(repo);
		}
	}
#endif

	apk_string_array_init(&args);
	apk_string_array_resize(&args, argc);
	memcpy(args->item, argv, argc * sizeof(*argv));

	r = applet->main(ctx, &db, args);
	apk_db_close(&db);

err_and_usage:
	if (r == -EINVAL)
		r = usage(applet);
	if (r == -ESHUTDOWN)
		r = 0;
err:
	if (ctx)
		free(ctx);

	fetchConnectionCacheClose();
	return r;
}
