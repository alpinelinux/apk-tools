apk-mkndx(8)

# NAME

apk mkndx - create apkv3 repository index file from packages

# SYNOPSIS

*apk mkndx* [<_options_>...] _packages_...

# DESCRIPTION

*apk mkndx* creates a repository index from a list of package files. See
*apk-repositories*(8) for more information on repository indicies.

# OPTIONS

*-d, --description* _TEXT_
	Add a description to the index. Upstream, this is used to add version
	information based on the git commit SHA of aports HEAD at the time of
	index generation.

*--hash* _HASH_
	Use _HASH_ as the algorithm for apk v3 integrity. Currently supported:
	- sha256 (default)
	- sha256-160

	The *sha256-160* is allowed to generate index compatible with old
	prereleases of apkv3 that do no handle longer hashes correctly.

*-o, --output* _FILE_
	Output generated index to _FILE_.

*-x, --index* _INDEX_
	Read an existing index from _INDEX_ to speed up the creation of the new
	index by reusing data when possible.

*--rewrite-arch* _ARCH_
	Set all package's architecture to _ARCH_.
