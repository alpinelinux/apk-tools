apk-world(5)

# NAME

*/etc/apk/world* - list of explicitly installed packages

# DESCRIPTION

At /etc/apk/world, apk maintains the _world_, or list of explicitly installed
packages. This is a plaintext file with one dependency per line.

If you edit this file manually, you should run *apk-fix*(8) to apply the
changes.

# PACKAGE SPECIFICATION

Specifying a package name with no other modifiers will install the latest
version of that package from the first repository in which it is available.

To pin a package to a tagged repository, use the format *pkgname@tagname*, e.g.
*busybox@edge*. See *apk-repositories*(5) for details on tagged package
repositories.

To constrain the acceptable versions of the package, use the *=*, *<*, *>*,
*>=*, or *~=* operators. Respectively, these require the package is equal to,
less than, greater than, or greater than or equal to the specified version. The
*~=* operator constrains the package to the version numbers specified, but will
not constrain any unspecified version numbers.

A dependency has the format *name{@tag}{[<>~=]version}*.

*busybox*
	Installs busybox from the untagged repository from which it is
	available.

*busybox@edge*
	Allows installation of busybox and it's dependencies from a repository
	tagged with "edge". Tagged repositories will not be prioritized. If a
	version from an untagged repository is a better fit it will be used.

*busybox=1.6.1*
	Install busybox version 1.6.1.

*busybox>1.6.1*
	Install a busybox version greater than 1.6.1.

*busybox>=1.6.1*
	Install a busybox version greater than or equal to 1.6.1.

*busybox<1.6.1*
	Install a busybox version less than 1.6.1.

*busybox~=1.6*
	Install any busybox version between 1.6.0 (inclusive) and 1.7.0
	(exclusive).
