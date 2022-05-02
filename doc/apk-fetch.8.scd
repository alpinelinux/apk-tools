apk-fetch(8)

# NAME

apk fetch - download packages from global repositories to a local directory

# SYNOPSIS

*apk fetch* [<_options_>...] _packages_...

# DESCRIPTION

*apk fetch* downloads the requested packages from the configured package
repositories (see *apk-repositories*(5)) to a local directory. The current
working directory is used as the destination directory unless *-o* is
specified.

# OPTIONS

*-L, --link*
	Create hard links if possible.

*-o, --output* _DIR_
	Write the downloaded file(s) to _DIR_.

*-R, --recursive*
	Fetch packages and all of their dependencies.

*-s, --stdout*
	Dump the .apk file(s) to stdout.

	*Note*: this option is incompatible with *-o*, *-R*, and the global
	*--progress* option.

*-w, --world*
	Download packages needed to satisfy _world_. Implies *--recursive*.

*--simulate*
	Simulate the requested operation without making any changes.

	*Note*: this option is unreliable if needed indexes are not up-to-date
	as this omits refresing or downloading of missing indexes.

*--url*
	Print the full URL for downloaded packages.
