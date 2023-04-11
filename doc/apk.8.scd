apk(8)

# NAME

apk - Alpine Package Keeper

# SYNOPSIS

*apk* [<_options_>...] _command_ [<_arguments_>...]

# DESCRIPTION

*apk* manages packages installed on the system. The set of top level packages
to install is called the _world_ (see *apk-world*(5)). *apk* supports various
sub-commands to query and manipulate _world_ and local & remote package
repositories.

# COMMANDS

Each command is documented in detail on its manual page.

## PACKAGE INSTALLATION AND REMOVAL

|[ *apk-add*(8)
:< Add packages to _world_ and commit changes
|  *apk-del*(8)
:  Remove packages from _world_ and commit changes

## SYSTEM MAINTENANCE

|[ *apk-fix*(8)
:< Fix, reinstall or upgrade packages without modifying _world_
|  *apk-update*(8)
:  Update repository indexes
|  *apk-upgrade*(8)
:  Install upgrades available from repositories
|  *apk-cache*(8)
:  Manage the local package cache

## QUERYING PACKAGE INFORMATION

|[ *apk-info*(8)
:< Give detailed information about packages or repositories
|  *apk-list*(8)
:  List packages matching a pattern or other criteria
|  *apk-dot*(8)
:  Render dependencies as graphviz graphs
|  *apk-policy*(8)
:  Show repository policy for packages
|  *apk-search*(8)
:  Search for packages by name or description

## REPOSITORY MAINTENANCE

|[ *apk-index*(8)
:< Create repository index file from packages
|  *apk-fetch*(8)
:  Download packages from repositories to a local directory
|  *apk-manifest*(8)
:  Show checksums of package contents
|  *apk-verify*(8)
:  Verify package integrity and signature

## MISCELLANEOUS

|[ *apk-audit*(8)
:< Audit system for changes
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
	Interactive mode can be made the default when running on a tty,
	by creating /etc/apk/interactive as an empty file.

*-p, --root* _ROOT_
	Manage file system at _ROOT_.

*-q, --quiet*
	Print less information.

*-U, --update-cache*
	Alias for '--cache-max-age 1'.

*-v, --verbose*
	Print more information (can be specified twice).

*-V, --version*
	Print program version and exit.

*-X, --repository* _REPO_
	Specify additional package repository. This option can be specified
	multiple times.

*--allow-untrusted*
	Install packages with untrusted signature or no signature.

*--arch* _ARCH_
	Temporarily override architecture, to be combined with --root.

*--cache-dir* _CACHEDIR_
	Temporarily override the cache directory. _CACHEDIR_ is treated relative
	to the _ROOT_.

*--cache-max-age* _AGE_
	Maximum AGE (in minutes) for index in cache before it's refreshed.

*--force-binary-stdout*
	Continue even if binary data will be printed to the terminal.

*--force-broken-world*
	Continue even if _world_ cannot be satisfied.

*--force-missing-repositories*
	Continue even if some of the repository indexes are not available.

*--force-non-repository*
	Continue even if packages may be lost on reboot. This can happen when
	running in run-from-tmpfs mode, and installing non-repository package.

*--force-old-apk*
	Continue even if packages use unsupported features.

*--force-overwrite*
	Overwrite files in other packages.

*--force-refresh*
	Do not use cached files (local or from proxy).

*--keys-dir* _KEYSDIR_
	Override directory of trusted keys. This is treated relative to _ROOT_.

*--no-cache*
	Do not use any local cache path.

*--no-check-certificate*
	Do not validate the HTTPS server certificates.

*--no-interactive*
	Disable interactive mode.

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
	Purge modified configuration and cached packages. Enables deletion of
	modified configuration files on package removal. On cache clean action
	this enables deletion of unneeded cached packages (uninstalled packages
	on tmpfs installations or all packages on disk installations).

*--repositories-file* _REPOFILE_
	Override system repositories, see *apk-repositories*(8). Specifying this
	option overrides the normal repositories file and repositories.d directory
	processing. The given _REPOFILE_ is relative to the startup directory since
	apk 2.12.0_rc2.

*--wait* _TIME_
	Wait for TIME seconds to get an exclusive repository lock before
	failing.

# COMMIT OPTIONS

The following options are available for all commands which commit the database.

*-s, --simulate*
	Simulate the requested operation without making any changes. The database
	is opened in read only mode, and auto-updating of indexes is disabled.
	You may want to run "apk update" before running a simulation to make sure
	it is done with up-to-date repository indexes.

*--clean-protected*
	Do not create .apk-new files in configuration directories.

*--overlay-from-stdin*
	Read list of overlay files from stdin. Normally this is used only during
	initramfs when booting run-from-tmpfs installation.

*--no-scripts*
	Do not execute any scripts. Useful for extracting a system image for
	different architecture on alternative _ROOT_.

*--no-commit-hooks*
	Skip pre/post hook scripts (but not other scripts).

*--initramfs-diskless-boot*
	Used by initramfs when it's recreating root tmpfs. This enables selected
	force options to minimize failure, and disables commit hooks, among
	other features.


# SOURCE OPTIONS

The following options are available for all commands which operate on the
package indexes only.

*--from* _FROMSPEC_
	Search packages from: *system* (all system sources), *repositories*
	(exclude installed database), *installed* (exclude normal repositories)
	or *none* (commandline repositories only).

# NOTES

This apk has coffee making abilities.
