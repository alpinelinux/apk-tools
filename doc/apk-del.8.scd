apk-del(8)

# NAME

apk del - remove packages from _world_ and commit changes

# SYNOPSIS

*apk del* [<_options_>...] _packages_...

# DESCRIPTION

*apk del* removes packages from _world_ and uninstalls them if no longer
required by any other packages.

# OPTIONS

*apk del* supports the commit options described in *apk*(8), as well as the
following options:

*-r, --rdepends*
	Recursively delete all top-level reverse dependencies, too.

# AUTHORS

Natanael Copa <ncopa@alpinelinux.org>++
Timo Teräs <_timo.teras@iki.fi_>
