apk-dot(8)

# NAME

apk dot - generate graphviz graphs

# SYNOPSIS

*apk dot* [<_options_>...] [_pkgmask_...]

# DESCRIPTION

*apk dot* generates graphviz dependency graphs for packages matching the masks
specified, or for every known package if unspecified (this will generate a
large and unwieldy graph).

# OPTIONS

*--errors*
	Graph only relationships considered erroneous, e.g. cycles and missing
	packages.

*--installed*
	Consider only installed packages.

# AUTHORS

Natanael Copa <ncopa@alpinelinux.org>++
Timo Teräs <_timo.teras@iki.fi_>
