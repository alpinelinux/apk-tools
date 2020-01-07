apk-del(8)

# NAME

apk del - remove packages from _world_ and commit changes

# SYNOPSIS

*apk del* [<_options_>...] _packages_...

# DESCRIPTION

*apk del* removes packages from _world_ and uninstalls them if no longer
required by any other packages.

# OPTIONS

## COMMIT OPTIONS

*apk del* commits the database, and supports the same options as other commit
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

## DELETE OPTIONS

The following options affect the *delete* operation.

*-r, --rdepends*
	Recursively delete all top-level reverse dependencies, too.

# AUTHORS

Natanael Copa <ncopa@alpinelinux.org>++
Timo Teräs <_timo.teras@iki.fi_>
