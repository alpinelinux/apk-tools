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

*-a, --available*
	Consider only available packages.

*-d, --depends*
	List packages by dependency.

*-I, --installed*
	Consider only installed packages.

*--manifest*
	List installed packages in format `<name> <version>`.

*-o, --origin*
	List packages by origin.

*-O, --orphaned*
	Consider only orphaned packages.

*-P, --providers*
	List packages by provider.

*-u, --upgradable, --upgradeable*
	Consider only upgradable packages.
