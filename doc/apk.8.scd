apk(8)

# NAME

apk - Alpine Package Keeper

# SYNOPSIS

*apk* [<_options_>...] _command_ [<_arguments_>...]

# DESCRIPTION

*apk* manages packages installed on the system. The set of top level constraints
on system packages is called the _world_ (see *apk-world*(5)).

*apk* supports various sub-commands to query and manipulate _world_ and package
repositories.

All apk commands which modify the database are logged to /var/log/apk.log.

By default apk is non-interactive. See *FILES* or *--interactive* on changing
this default to be interactive.


# COMMANDS

Each command is documented in detail on its manual page.

## PACKAGE INSTALLATION AND REMOVAL

|[ *apk-add*(8)
:< Add or modify constraints in _world_ and commit changes
|  *apk-del*(8)
:  Remove constraints from _world_ and commit changes

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

|[ *apk-query*(8)
:< Query information about packages by various criteria
|  *apk-list*(8)
:  List packages matching a pattern or other criteria
|  *apk-dot*(8)
:  Render dependencies as graphviz graphs
|  *apk-policy*(8)
:  Show repository policy for packages
|  *apk-search*(8)
:  Search for packages by name or description
|  *apk-info*(8)
:< Give detailed information about packages or repositories

## REPOSITORY AND PACKAGE MAINTENANCE

|[ *apk-mkndx*(8)
:< Create repository index (v3) file from packages
|  *apk-mkpkg*(8)
:  Create package (v3)
|  *apk-index*(8)
:  Create repository index (v2) file from packages
|  *apk-fetch*(8)
:  Download packages from repositories to a local directory
|  *apk-manifest*(8)
:  Show checksums of package contents
|  *apk-extract*(8)
:  Extract package file contents
|  *apk-verify*(8)
:  Verify package integrity and signature
|  *apk-adbsign*(8)
:  Sign, resign or recompress v3 packages and indexes

## MISCELLANEOUS

|[ *apk-audit*(8)
:< Audit system for changes
|  *apk-stats*(8)
:  Show statistics about repositories and installations
|  *apk-version*(8)
:  Compare package versions or perform tests on version strings
|  *apk-adbdump*(8)
:  Dump v3 files in textual representation
|  *apk-adbgen*(8)
:  Generate v3 files from text representation
|  *apk-convdb*(8)
:  Convert v2 installed database to v3 format
|  *apk-convndx*(8)
:  Convert v2 indexes to v3 format

# GLOBAL OPTIONS

The following options are available for all commands.

*-h, --help*
	Print the list of all commands with descriptions.

*-f, --force*
	Enable selected --force-\* options (deprecated).

*-i, --interactive, --no-interactive*
	Ask or don't ask for confirmation before performing certain operations.
	Interactive mode can be made the default when running on a tty,
	by creating /etc/apk/interactive as an empty file.

*-p, --root* _ROOT_
	Manage file system at _ROOT_.

*-q, --quiet*
	Print less information.

*-U, --update-cache*
	Alias for '--cache-max-age 0'.

*-v, --verbose*
	Print more information (can be specified twice).

*-V, --version*
	Print program version and exit.

*-X, --repository* _REPO_
	Specify additional package repository. *apk-repositories*(5) specified
	commands are not parsed (use *--repository-config* for that).
	Additionally, relative paths are accepted and interpreted relative
	to the startup directory.

*--allow-untrusted*
	Install packages with untrusted signature or no signature.

*--arch* _ARCH_
	Temporarily override architectures. The first given *--arch* will be used
	as the primary architecture. It will be used to determine the paths where
	to download package indexes from. The additional architectures specify
	compatible packages which are considered for installation.

	When used with --root the architecture will also be saved.

*--cache-dir* _CACHEDIR_
	Temporarily override the cache directory. _CACHEDIR_ is treated relative
	to the _ROOT_.

*--cache-max-age* _AGE_
	Maximum AGE (in minutes) for index in cache before it's refreshed. *0*
	means always refresh.

*--cache-packages, --no-cache-packages*
	Store a copy of packages at installation time to cache. Enabled automatically
	if */etc/apk/cache* symlink exists.

*--cache-predownload, --no-cache-predownload*
	Download needed packages to cache before starting to commit a transtaction.
	Requires cache to be configured to be functional. Implies *--cache-packages*.

*--force-binary-stdout*
	Continue even if binary data will be printed to the terminal.

*--force-broken-world*
	DANGEROUS: Delete world constraints until a solution without conflicts
	is found. This does not allow installation of packages with unsatisfiable
	dependencies and is mainly intended to be used initramfs boot and is
	implied by *--initramfs-diskless-boot*.  The primary purpose is to allow
	run-from-tmpfs systems to boot if media was upgraded and some packages
	are no longer available in the new release.

	APK will try to determine the world constraints that causes packages
	with conflicting dependencies and start disabling the world constraints
	in this order until a satisfiable set of constraints is left. Using this
	switch on hard disk installation will likely result in unexpected removal
	of some packages. If uncertain, use with *--interactive* or *--simulate*
	first.

*--force-missing-repositories*
	Continue even if some of the repository indexes are not available.

*--force-no-chroot*
	Disable chroot for scripts. This can be used for rootfs creation when
	chroot is not available. Scripts running outside a chroot environment
	may modify and damage the host system.

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
	Override the default system trusted keys directories. If specified the
	only this directory is processed. The _KEYSDIR_ is treated relative
	to _ROOT_.

*--legacy-info, --no-legacy-info*
	Print output from "info" applet in legacy format or new "query" format.
	Defaults to no currently, but the default is subject to change to yes
	in a future release.

*--no-cache*
	Do not use any local cache path.

*--no-check-certificate*
	Do not validate the HTTPS server certificates.

*--no-logfile*
	Disable writing to the log file.

*--no-network*
	Do not use the network. The cache is still used when possible.

*--preserve-env*
	Pass user environment down to scripts (excluding variables starting
	APK_ which are reserved).

*--print-arch*
	Print default arch and exit.

*--progress, --no-progress*
	Enable or disable progress bar. Defaults to yes for TTYs.

*--progress-fd* _FD_
	Write progress to the specified file descriptor.

*--purge*
	Purge modified configuration and cached packages. Enables deletion of
	modified configuration files on package removal. On cache clean action
	this enables deletion of unneeded cached packages (uninstalled packages
	on tmpfs installations or all packages on disk installations).

*--repositories-file* _REPOFILE_
	Override system repositories, see *apk-repositories*(5). Specifying this
	option overrides the normal repositories file and repositories.d directory
	processing. The given _REPOFILE_ is relative to the startup directory since
	apk 2.12.0_rc2.

*--repository-config* _REPOCONFIG_
	Specify additional package repository configuration. The _REPOCONFIG_ is
	parsed exactly the same way as if it was read from a *apk-repositories*(5)
	specified *.list* file.

*--timeout* _TIME_
	Timeout network connections if no progress is made in TIME seconds.
	The default is 60 seconds.

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

*--no-commit-hooks*
	Skip pre/post hook scripts (but not other scripts).

*--no-scripts*
	Do not execute any scripts. Useful for extracting a system image for
	different architecture on alternative _ROOT_.

*--initramfs-diskless-boot*
	Used by initramfs when it's recreating root tmpfs. This enables selected
	force options to minimize failure, and disables commit hooks, among
	other features.

# GENERATION OPTIONS

The following options are available for all commands which generate APKv3 files.

*-c, --compression* _ALGORITHM[:LEVEL]_
	Compress the file with given _ALGORITHM_ and _LEVEL_. Supported algorithms:
	- none
	- deflate (level 1-9)
	- zstd (level 1-22)

*--sign-key* _KEYFILE_
	Sign the file with a private key in the specified _KEYFILE_.

# ENVIRONMENT

*APK_CONFIG*
	Override the default config file name. See */etc/apk/config*

*LANG*
	Used to determine if UTF-8 is supported, and set the default progress
	character accordingly.

*SOURCE_DATE_EPOCH*
	See *apk-index*(8).

*TERM*
	Used to determine if the terminal is dumb or not. Progress bar is not
	enabled on dumb terminals by default.

## Variables to configure built-in libfetch

*FETCH_BIND_ADDRESS*
	A local IP address to which libfetch will bind all sockets it creates.
	Can be useful for source routing.

*NETRC*
	Specify the *.netrc* file to read for authentication secrets. If not
	set, defaults to *$HOME/.netrc*.

*HTTP_AUTH*++
*HTTP_REFERER*++
*HTTP_USER_AGENT*
	Specify a custom HTTP level *Authorization*, *Referer* or *User-Agent* header.

*HTTP_PROXY*, *http_proxy*++
*HTTPS_PROXY*, *https_proxy*++
	If set, these variables should contain the proxy URL for *http*
	and *https* connections respectively.

*HTTP_PROXY_AUTH*
	Specify a HTTP *Proxy-Authorization* header. Used only if the connection
	is established through a configured HTTP proxy.

*NO_PROXY*, *no_proxy*
	Comma-separated list of domain extensions or CIDR notation IP addresses
	to which a proxy should _not_ be used for.  This is used explicitly to
	test the URL hostname portion only. That is, specifying an IP address
	or CIDR block will not match a DNS name that resolves to the IP address.

*SSL_CLIENT_CERT_FILE*++
*SSL_CLIENT_KEY_FILE*
	Override default SSL client certificate and corresponding private key
	filename.

*SSL_NO_VERIFY_HOSTNAME*
	If set to anything, disables the server certificate name verification.

## Environment for the scripts APK executes

Normally *apk* will execute scripts with a sanitized, minimal environment
containing only *PATH*. See also *--preserve-env* to pass additional
environment variables.

Before executing a script, apk will set working directory as _ROOT_ and
performs a chroot unless *--force-no-chroot* is specified. In either case,
the script working directory should be treated as the system root.

The environment variables defined by APK are the following:

*APK_PACKAGE*
	Package name (package scripts only).

*APK_SCRIPT*
	Set to one of the package or commit script types. Use this to determine
	the script hook type if needed. The filename (\$0) is not reliable since
	apk prefers to execute package scripts from a memfd file.

# FILES

## Configuration files

*/etc/apk/config*++
*/lib/apk/config*
	Default global options. Only the first file existing in the above list is
	read and parsed. The file in */lib* is intended to be for distribution default
	options, which can be then overridden by user with the file in */etc*. See also
	*APK_CONFIG* environment variable.

	A configuration file contains one long option per line. For example:
		no-cache++
timeout 120

*/etc/apk/interactive*
	If this file exists and apk is running on a tty, *--interactive*
	mode is enabled by default.

## Configuration files (relative to --root)

*/etc/apk/arch*
	The CPU architecture for this database. See *apk-package*(5) section
	on package metadata field *arch* for the list.

*/etc/apk/cache*
	This is expected to be a symlink to directory what apk will use
	as package cache. See also *apk-cache*(5) and *apk-cache*(8).

*/etc/apk/commit_hooks.d/\**++
*/lib/apk/commit_hooks.d/\**
	Hook scripts which are executed before anything has been written to the
	filesystem and after all the changes have been commited. The script
	executed gets as an argument the stage name (*pre-commit* or
	*post-commit*). If the script returns failure during *pre-commit* stage,
	the commit is aborted.

	See also the ENVIRONMENT section for the environment variables.

	If *--no-scripts* or *--no-commit-hooks* option is specified, these
	hook scripts are not executed.

*/etc/apk/keys*++
*/lib/apk/keys*
	Directories for trusted signing keys. The directories are enumerated in
	the above mentioned order. Once a given filename is seen, any file of
	the same name in subsequent directories is ignored.

*/etc/apk/protected_paths.d/\*.list*
	Configuration files to specify how to treat changes to specified
	directory or file masks. The file format is further documented in
	*apk-protected_paths*(5).

*/etc/apk/repositories*++
*/etc/apk/repositories.d/\*.list*++
*/lib/apk/repositories.d/\*.list*
	Configuration files to specify repositories. The directories are
	enumerated in the above mentioned order. Once a given filename is seen,
	any file of the same name in subsequent directories is ignored.
	See *apk-repositories*(5) for details.

*/etc/apk/world*
	Top level requirements and constraints on what should be installed.
	See *apk-world*(5) for details.

## Configuration files for built-in libfetch

*/etc/apk/ca.pem*
	CA certificate store bundle for verifying server certificates.
	If not present, the default system CA store is used.

*/etc/apk/crl.pem*
	CRL store to check the server certificates against.

*/etc/apk/cert.key*
	Client certificate private key.

*/etc/apk/cert.pem*
	Client certificate to use for authentication.

## System files

*/lib/apk/db/lock*
	A lock file used to allow only one concurrent write transaction on
	the system.

*/lib/apk/db/installed*
	Database of installed packages and their contents.

*/lib/apk/db/scripts.tar*
	Collection of all package scripts from currently installed packages.

*/lib/apk/db/triggers*
	List of triggers rules for currently installed packages.

*/lib/apk/db-uvol*
	Database symlink or a directory with similar structure as */lib/apk/db/*,
	but which used for package content when managed using OpenWRT *uvol*
	volume manager.

*/lib/apk/exec*
	Temporary directory for extraction and execution of package scripts
	and triggers.

*/var/log/apk.log*
	Log file for changes done to the system.

# NOTES

This apk has coffee making abilities.
