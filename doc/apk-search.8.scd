apk-search(8)

# NAME

apk search - search for packages by name or description

# SYNOPSIS

*apk search* [<_options_>...] _pattern_...

# DESCRIPTION

*apk search* searches all repositories for packages matching at least one
pattern. If no pattern is given, it lists all packages in the configured
repositories (see *apk-repositories*(5)). A pattern matches if it is a
case-insensitive substring of the package name.

# OPTIONS

In addition to the global options (see *apk*(8)), *apk search* supports the
following options:

*-a, --all*
	Print all matching package versions. By default, *apk* only shows the
	latest version.

*-d, --description*
	Also search for _pattern_ in the package description. By default, *apk*
	does not search package descriptions.

*-e, -x, --exact*
	Match package names exactly.

*--has-origin*
	Match by package origin. Shows all packages whose base package name
	matches _pattern_ exactly. Implies *--all* and *--exact*.

*-o, --origin*
	Print base package name.

*-r, --rdepends*
	Print reverse dependencies (other packages which depend on the
	package).
