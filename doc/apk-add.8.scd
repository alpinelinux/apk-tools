apk-add(8)

# NAME

apk add - add packages to _world_ and commit changes

# SYNOPSIS

*apk add* [<_options_>...] _packages_...

# DESCRIPTION

*apk add* adds the requested packages to _world_ and installs (or upgrades)
them if not already present, ensuring all dependencies are met.

# OPTIONS

*apk add* supports the commit options described in *apk*(8), as well as the
following options:

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

*--no-chown*
	Do not change file owner or group. By default apk will manage the file
	ownership when running as root. However, this option is turned on when
	running as non-root user, as changing file ownership is not permitted
	by the system then.

# AUTHORS

Natanael Copa <ncopa@alpinelinux.org>++
Timo Teräs <timo.teras@iki.fi>
