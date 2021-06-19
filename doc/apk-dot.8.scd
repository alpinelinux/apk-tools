apk-dot(8)

# NAME

apk dot - generate graphviz graphs

# SYNOPSIS

*apk dot* [<_options_>...] [_pkgmask_...]

# DESCRIPTION

*apk dot* renders package dependencies as graphviz graphs.

The graph is generated for the packages matching the masks given, or for every
known package if unspecified (this will generate a large and unwieldy graph).

# OPTIONS

*--errors*
	Consider only packages with errors. This is useful for visually reporting
	e.g. cyclic dependencies and missing packages.

*--installed*
	Consider only installed packages.
