apk-info(8)

# NAME

apk info - print detailed information about packages

# SYNOPSIS

*apk info* [<_options_>...] _packages_...

*apk info* -W _file_

# DESCRIPTION

*apk info* prints information known about the listed packages. By default, it
prints the description, webpage, and installed size of the package (equivalent
to *apk info -dws*).

Each field printed is prefaced by the name of the package and its package
version, then the field to be displayed, and a newline. The following lines
display the appropriate information, then an empty line terminates that field.

*apk info -W* _file_ prints the package which owns the specified file.

# OPTIONS

*-a, --all*
	List all information known about the package.

*-d, --description*
	Print the package description.

*-e, --installed*
	Check if the package is installed, printing its name and exiting with
	status code zero if so, or exiting with a nonzero status code otherwise.

*-L, --contents*
	List files included in the package.

*-i, --install-if*
	List the package's install_if rule, if configured (i.e. the conditions
	under which this package will be installed automatically).

*-I, --rinstall-if*
	List other packages whose install_if rules refer to this package.

*-r, --rdepends*
	List reverse dependencies of the package (all other packages which
	depend on the package).

*-R, --depends*
	List the dependencies of the package.

*-s, --size*
	Print the package's installed size.

*-w, --webpage*
	Print the URL for the package's upstream webpage.

*-W, --who-owns*
	Print the package which owns the specified file.

*--license*
	Print the package SPDX license identifier.

*--replaces*
	List the other packages for which this package is marked as a
	replacement.

*--triggers*
	Print active triggers for the package.

# AUTHORS

Natanael Copa <ncopa@alpinelinux.org>++
Timo Teräs <_timo.teras@iki.fi_>
