apk-add(8)

# NAME

apk add - add packages to _world_ and commit changes

# SYNOPSIS

*apk add* [<_options_>...] _packages_...

# DESCRIPTION

*apk add* adds the requested packages to _world_ and installs (or upgrades)
them if not already present, ensuring all dependencies are met.

To upgrade individual packages without modifying _world_ use *apk-fix*(8).

By default *apk* tries to select a set of packages so that all dependencies
are satisfied. This means that some packages can be held back in an older
version if there is direct or implicit dependencies to the older version.

# OPTIONS

*apk add* supports the commit options described in *apk*(8), as well as the
following options:

*--initdb*
	Initialize a new package database.

*-l, --latest*
	Always choose the latest package by version. However, the versions
	considered are based on the package pinning. Primarily this overrides
	the default heuristic and will cause an error to displayed if all
	dependencies cannot be satisfied.

*-u, --upgrade*
	Upgrade _packages_ and their dependencies. Normally *apk add* will
	avoid changing installed package unless it is required by the newly
	added _packages_ or their dependencies. This changes the default
	preference to upgrading the package to the latest installable version.

*-t, --virtual* _NAME_
	Create virtual package _NAME_ with given dependencies. This new package
	will get the _packages_ as dependencies instead of _world_. Finally the
	_NAME_ is added to _world_. An optional version specifier for the virtual
	package can be given via syntax _NAME_=_VERSION_. The version defaults
	to synthesized version based on time.

	One can use this to ensure that selected set of packages are installed,
	and later the temporary modification be undone with *apk-del*(8) _NAME_
	without removing packages that were installed earlier.

*--no-chown*
	Do not change file owner or group. By default apk will manage the file
	ownership when running as root. However, this option is turned on when
	running as non-root user, as changing file ownership is not permitted
	by the system then.
