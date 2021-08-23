apk-list(8)

# NAME

apk list - list packages matching a pattern or other criteria

# SYNOPSIS

*apk list* [<_options_>...] _pattern_...

# DESCRIPTION

*apk list* searches package indicies for packages matching the given patterns
and prints any matching packages.

The patterns are matched with *fnmatch*(3), which behaves similarly to shell
globbing.

# OPTIONS

*-I, --installed*
	Consider only installed packages.

*-O, --orphaned*
	Consider only orphaned packages.

*-a, --available*
	Consider only available packages.

*-u, --upgradable, --upgradeable*
	Consider only upgradable packages.

*-o, --origin*
	List packages by origin.

*-d, --depends*
	List packages by dependency.

*-P, --providers*
	List packages by provider.
