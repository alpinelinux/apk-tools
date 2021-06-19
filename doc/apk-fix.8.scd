apk-fix(8)

# NAME

apk fix - repair packages or system

# SYNOPSIS

*apk fix* [<_options_>...] [_packages_...]

# DESCRIPTION

*apk fix* applies repair strategies to correct errors in the installation of
the specified packages, or all installed packages if none are specified.

# OPTIONS

*apk fix* supports the commit options described in *apk*(8), as well as the
following options:

*-d, --depends*
	Also fix dependencies of specified packages.

*-r, --reinstall*
	Reinstall packages (default).

*-u, --upgrade*
	Upgrade name _PACKAGE_ if an upgrade exists and does not break
	dependencies.

*-x, --xattr*
	Fix packages with broken xattrs.

*--directory-permissions*
	Reset all directory permissions.
