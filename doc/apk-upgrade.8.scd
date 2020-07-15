apk-upgrade(8)

# NAME

apk upgrade - upgrade installed packages

# SYNOPSIS

*apk upgrade* [<_options_>...] [<_packages_>...]

# DESCRIPTION

*apk upgrade* upgrades installed packages to the latest version available from
configured package repositories (see *apk-repositories*(5)).

# OPTIONS

*apk upgrade* supports the commit options described in *apk*(8), as well as the
following options:

*-a, --available*
	Reset all packages to versions available from current repositories.
	This resets all versioned dependencies in _world_ (see *apk-world*(5)).
	Additionally, packages are selected from active repositories if possible
	even if it means replacing or downgrading the package.

	This is useful to reset system against new set of packages after updating
	repositories.

*-l, --latest*
	Always choose the latest package by version. However, the versions
	considered are based on the package pinning. Primarily this overrides
	the default heuristic and will cause an error to displayed if all
	dependencies cannot be satisfied.

*--no-self-upgrade*
	Do not do an early upgrade of the 'apk-tools' package.

*--self-upgrade-only*
	Only perform a self-upgrade of the 'apk-tools' package.

# AUTHORS

Natanael Copa <ncopa@alpinelinux.org>++
Timo Teräs <timo.teras@iki.fi>
