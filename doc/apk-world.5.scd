apk-world(5)

# NAME

*/etc/apk/world* - list of explicitly installed packages

# DESCRIPTION

At /etc/apk/world, apk maintains the _world_, or list of explicitly installed
packages. This is a plaintext file with one package spec per line.

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

*busybox*
	Installs busybox from the first repository from which it is available.

*busybox@edge*
	Installs busybox from the first repository tagged "edge" from which
	it's available. If busybox is _not_ available in repositories with this
	tag, it will cause an error. When resolving dependencies of tagged
	requirements, untagged repositories are preferred, but repositories
	sharing the same tag will be considered if necessary.

*busybox=1.6.1*
	Install busybox version 1.6.1.

*busybox>1.6.1*
	Install a busybox version greater than 1.6.1.

*busybox>1.6.1*
	Install a busybox version greater than or equal to 1.6.1.

*busybox<1.6.1*
	Install a busybox version less than 1.6.1.

*busybox~=1.6*
	Install any busybox version between 1.6.0 (inclusive) and 1.7.0
	(exclusive).

# AUTHORS

Natanael Copa <ncopa@alpinelinux.org>++
Timo Teräs <timo.teras@iki.fi>
