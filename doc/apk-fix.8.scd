apk-fix(8)

# NAME

apk fix - repair packages or system

# SYNOPSIS

*apk fix* [<_options_>...] [_packages_...]

# DESCRIPTION

*apk fix* applies repair strategies to correct errors in the installation of
the specified packages, or all installed packages if none are specified.

# OPTIONS

## COMMIT OPTIONS

*apk fix* commits the database, and supports the same options as other commit
operations.

*-s, --simulate*
	Simulate the requested operation without making any changes.

*--clean-protected*
	Do not create .apk-new files in configuration directories.

*--overlay-from-stdin*
	Read list of overlay files from stdin.

*--no-scripts*
	Do not execute any scripts.

*--no-commit-hooks*
	Skip pre/post hook scripts (but not other scripts).

*--initramfs-diskless-boot*
	Enables options for diskless initramfs boot (e.g. skip hooks).

## FIX OPTIONS

The following options affect the *fix* operation.

*-d, --depends*
	Also fix dependencies of specified packages.

*-r, --reinstall*
	Reinstall packages (default).

*-u, --upgrade*
	When fixing packages which are already installed, upgrade them rather
	than considering the requirement fulfilled by the current installation.

*-x, --xattr*
	Fix packages with broken xattrs.

*--directory-permissions*
	Reset all directory permissions.

# AUTHORS

Natanael Copa <ncopa@alpinelinux.org>++
Timo Teräs <_timo.teras@iki.fi_>
