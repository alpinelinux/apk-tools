apk(8)

# NAME

apk - Alpine Package Keeper

# SYNOPSIS

*apk* [<_options_>...] _command_ [<_arguments_>...]

# DESCRIPTION

*apk* manages packages installed on the system. The set of installed packages
is called the _world_ (see *apk-world*(5)). *apk* supports various sub-commands
to query and manipulate _world_ and local & remote package repositories.

# COMMANDS

Each command is documented in detail on its manual page.

## PACKAGE INSTALLATION AND REMOVAL

|[ *apk-add*(8)
:< Add packages to _world_ and commit changes
|  *apk-del*(1)
:  Remove packages from _world_ and commit changes

## SYSTEM MAINTENANCE

|[ *apk-fix*(8)
:< Check _world_ against the system and ensure consistency
|  *apk-update*(8)
:  Update repository indexes
|  *apk-upgrade*(8)
:  Install upgrades available from repositories
|  *apk-cache*(8)
:  Commands related to the management of an offline package cache

## QUERYING PACKAGE INFORMATION

|[ *apk-info*(8)
:< Give detailed information about packages or repositories
|  *apk-list*(8)
:  List packages matching a pattern or other criteria
|  *apk-dot*(8)
:  Generate graphviz graphs
|  *apk-policy*(8)
:  Show repository policy for packages

## REPOSITORY MAINTENANCE

|[ *apk-index*(8)
:< Create repository index file from packages
|  *apk-fetch*(8)
:  Download packages from global repositories to a local directory
|  *apk-manifest*(8)
:  Show checksums of package contents
|  *apk-verify*(8)
:  Verify package integrity and signature

## MISCELLANEOUS

|[ *apk-audit*(8)
:< Audit directories for changes
|  *apk-stats*(8)
:  Show statistics about repositories and installations
|  *apk-version*(8)
:  Compare package versions or perform tests on version strings

# GLOBAL OPTIONS

The following options are available for all commands.

*-f, --force*
	Enable selected --force-\* options (deprecated).

*-i, --interactive*
	Ask confirmation before performing certain operations.

*-p, --root* <_DIR_>
	Install packages to _DIR_.

*-q, --quiet*
	Print less information.

*-U, --update-cache*
	Alias for '--cache-max-age 1'.

*-v, --verbose*
	Print more information (can be specified twice).

*-V, --version*
	Print program version and exit.

*-X, --repository* <_REPO_>
	Use packages only from the specified repository.

*--allow-untrusted*
	Install packages with untrusted signature or no signature.

*--arch* _ARCH_
	Temporarily override architecture, to be combined with --root.

*--cache-dir* _CACHEDIR_
	Temporarily override the cache directory.

*--cache-max-age* _AGE_
	Maximum AGE (in minutes) for index in cache before it's refresh.

*--force-binary-stdout*
	Continue even if binary data will be printed to the terminal.

*--force-broken-world*
	Continue even if _world_ cannot be satisfied.

*--force-non-repository*
	Continue even if packages may be lost on reboot.

*--force-old-apk*
	Continue even if packages use unsupported features.

*--force-overwrite*
	Overwrite files in other packages.

*--force-refresh*
	Do not use cached files (local or from proxy).

*--keys-dir* _KEYSDIR_
	Override directory of trusted keys.

*--no-cache*
	Do not use any local cache path.

*--no-network*
	Do not use the network. The cache is still used when possible.

*--no-progress*
	Disable progress bar even for TTYs.

*--print-arch*
	Print default arch and exit.

*--progress*
	Show progress.

*--progress-fd* _FD_
	Write progress to the specified file descriptor.

*--purge*
	Delete modified configuration files on package removal and uninstalled
	packages from cache on cache clean.

*--repositories-file* _REPOFILE_
	Override repositories file, see *apk-repositories*(8).

*--wait* _TIME_
	Wait for TIME seconds to get an exclusive repository lock before
	failing.

# NOTES

This apk has coffee making abilities.

# AUTHORS

Natanael Copa <ncopa@alpinelinux.org>++
Timo Teräs <_timo.teras@iki.fi_>
