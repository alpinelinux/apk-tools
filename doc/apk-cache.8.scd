apk-cache(8)

# NAME

apk cache - manage a local cache of package files

# SYNOPSIS

*apk cache* [<_options_>...] clean

*apk cache* [<_options_>...] download

*apk cache* [<_options_>...] sync

# DESCRIPTION

Manage local package cache by removing obsolete packages, or downloading
missing or newer packages from the repositories.

*apk cache download* will fetch package files from the repositories and store
them in the cache, which must be enabled upfront (see *apk-cache*(5)).

*apk cache clean* will remove package files which are no longer necessary,
having been made obsolete by new versions or no longer being transitively
depended on by packages in _world_.

*apk cache sync* performs both operations.

# OPTIONS

*-l, --latest*
	Always choose the latest package by version. However, the versions
	considered are based on the package pinning. Primarily this overrides
	the default heuristic and will cause an error to displayed if all
	dependencies cannot be satisfied.

*-u, --upgrade*
	Upgrade _packages_ and it's dependencies. Normally *apk add* will
	avoid changing installed package unless it is required by the newly
	added _packages_ or their dependencies. This changes the default
	preference to upgrading the package to the latest installable version.

# AUTHORS

Natanael Copa <ncopa@alpinelinux.org>++
Timo Teräs <timo.teras@iki.fi>
