apk-upgrade(8)

# NAME

apk upgrade - upgrade installed packages

# SYNOPSIS

*apk upgrade* [<_options_>...]

# DESCRIPTION

*apk upgrade* upgrades installed packages to the latest version available from
configured package repositories (see *apk-repositories*(5)).

# OPTIONS

*apk upgrade* supports the commit options described in *apk*(8), as well as the
following options:

*-a, --available*
	Resets version constraints in _world_ (see *apk-world*(5)) and prefers
	replacing or downgrading packages if the currently installed package is
	no longer available from any repository (instead of holding them).

*-l, --latest*
	Disables normal heuristics for choosing which repository to install a
	package from, preferring only repositories from which the latest
	version is available. This has no effect on pinned packages.

*--no-self-upgrade*
	Do not do an early upgrade of the 'apk-tools' package.

*--self-upgrade-only*
	Only perform a self-upgrade of the 'apk-tools' package.

# AUTHORS

Natanael Copa <ncopa@alpinelinux.org>++
Timo Teräs <_timo.teras@iki.fi_>
