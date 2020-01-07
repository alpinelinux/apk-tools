apk-add(8)

# NAME

apk add - add packages to _world_ and commit changes

# SYNOPSIS

*apk add* [<_options_>...] _packages_...

# DESCRIPTION

*apk add* adds the requested packages to _world_ and installs (or upgrades)
them if not already present, ensuring all dependencies are met.

# OPTIONS

## COMMIT OPTIONS

*apk add* commits the database, and supports the same options as other commit
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

## ADD OPTIONS

The following options affect the *add* operation.

*--initdb*
	Initialize a new package database.

*-l, --latest*
	Disables normal heuristics for choosing which repository to install a
	package from, preferring only repositories from which the latest
	version is available. This has no effect on pinned packages.

*-u, --upgrade*
	When adding packages which are already installed, upgrade them rather
	than considering the requirement fulfilled by the current installation.

*-t, --virtual* _NAME_
	Instead of adding the specified packages to _world_, create a new
	virtual package with the listed packages as its dependencies, then add
	that package to _world_.

	The packages requested are added as transitive dependencies of the
	virtual package, and by deleting that package the *apk add* operation
	may be easily reverted later.

# AUTHORS

Natanael Copa <ncopa@alpinelinux.org>++
Timo Teräs <_timo.teras@iki.fi_>
