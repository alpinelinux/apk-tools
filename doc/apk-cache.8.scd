apk-cache(8)

# NAME

apk cache - manage a local cache of package files

# SYNOPSIS

*apk cache* [<_options_>...] clean

*apk cache* [<_options_>...] download

*apk cache* [<_options_>...] sync

# DESCRIPTION

*apk cache download* will fetch package files from the repositories and store
them in the cache, which must be enabled upfront (see *apk-cache*(5)).

*apk cache clean* will remove package files which are no longer necessary,
having been made obsolete by new versions or no longer being transitively
depended on by packages in _world_.

*apk cache sync* performs both operations.

# OPTIONS

*-l, --latest*
	Disables normal heuristics for choosing which repository to install a
	package from, preferring only repositories from which the latest
	version is available. This has no effect on pinned packages.

*-u, --upgrade*
	When caching packages which are already installed, prefer their upgrades
	rather than considering the requirement fulfilled by the current
	installation.

# AUTHORS

Natanael Copa <ncopa@alpinelinux.org>++
Timo Teräs <timo.teras@iki.fi>
