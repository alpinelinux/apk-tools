apk-repositories(5)

# NAME

*/etc/apk/repositories*++
*/etc/apk/repositories.d/\*.list*++
*/lib/apk/repositories.d/\*.list*++
	list of package repositories

# DESCRIPTION

*apk*(8) loads repository definitions from the above mentioned files.
The *repositories* file is first loaded. The *repositories.d* paths are
then processed if *--repositories-file* option was not used. The directories
are enumerated in the above mentioned order. Once a *.list* file of given
name is seen, any file of the same name in subsequent directories is ignored.

Each line of this file is of the following format:

	# comment++
\[@tag\] url

The optional *@tag* can be present to indicate that the repository should
not be used by default. Refer to *apk-world*(5) on how to enable installation
of packages from tagged repositories.

The *url* refers to a base repository path or index file ending in *.adb*.
Currently supported schemes are:
	- _http://_
	- _https://_
	- _file://_
	- local filesystem path

# REPOSITORY LAYOUT

If the *url* refers to an index file (ending in *.adb*), the path resolution
works as follows:
	- *url* is a URL to the index file
	- *base_url* is *url* with last component stripped off
	- default package path: *$base_url/$name-$version.apk*

Otherwise the *type* is one of the repository types, and the path resolution
works as follows:
	- *url* is the *base_url* to the repository
	- index is at *$base_url/$arch/APKINDEX.tar.gz*
	- default package path: *$base_url/$arch/$name-$version.apk*

If the index file has a *pkgname-spec* set, it is used to construct the package path.
Otherwise the default package path based on above rules is used.

# CREATING INDEXES AND REPOSITORIES

See *apk-mkndx*(8) on how to create index files and *apk-adbsign*(8) on modifying
signatures.

For the legacy index format refer to *apk-index*(8) for index files, *abuild-keygen*(1)
for information about generating keys, *abuild-sign*(1) for information about using
these keys to sign files.

*apk-verify*(8) can verify both new and old style index and package files.

# CLIENT INDEX UPDATING

*apk*(8) fetches and stores the index for each repository at a local cache
in */etc/apk/cache* or */var/cache/apk*. Refer to *apk-cache*(5) for more details.

Refer to *apk-keys*(5) on how the client needs to be configured for verifying
the index signatures.
