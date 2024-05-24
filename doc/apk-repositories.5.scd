apk-repositories(5)

# NAME

*/etc/apk/repositories*, */etc/apk/repositories.d/\*.list* - list of package
repositories

# DESCRIPTION

/etc/apk/repositories is the list of package repositories *apk*(8) uses to
retrieve package files for installation. Each line of this file specifies the
location of a package repository, and optionally a tag.

The location may be an _http://_, _https://_, or the path to a directory on
the local filesystem. A tagged repository is prefixed with the *@tag* specifier,
followed by a space and the repository location. For more information about
repository tags, see *apk-world*(5).

# REPOSITORY LAYOUT

Each repository must store an index at *$repository/$arch/APKINDEX.tar.gz*. See
*apk-index*(8) for information about generating this file. The packages
themselves are stored at *$repository/$arch/$pkgname-$pkgver-r$pkgrel.apk*.

*apk*(8) verifies that each of these files has a valid cryptographic signature
unless explicitly told not to via the *--allow-untrusted* flag. See
*abuild-keygen*(1) for information about generating keys, *apk-keys*(5) to add
keys to the list of trusted keys, *abuild-sign*(1) for information about using
these keys to sign files, and *apk-verify*(8) for information about verifying
those signatures.

# UPDATING INDICIES

*apk*(8) fetches and stores the index for each package repository at
*/var/cache/apk*. To fetch fresh indicies for all configured repositories, use
*apk-update*(8).
