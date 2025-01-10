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

*-e, --exists, --installed*
	Check package installed status. For each installed package, print it's
	name. The exit status is the number of given packages not installed.
	Thus, zero (or success) is returned if all named packages are installed.
	NOTE: *--installed* is deprecated and will be removed to allow
	the same option in *query* group to function.

*-L, --contents*
	List files included in the package.

*-P, --provides*
	List what the package provides.

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

*--install-if*
	List the package's install_if rule. When the dependencies in this list
	are satisfied, the package will be installed automatically.

*--license*
	Print the package SPDX license identifier.

*--replaces*
	List the other packages for which this package is marked as a
	replacement.

*--rinstall-if*
	List other packages whose install_if rules refer to this package.

*-t, --triggers*
	Print active triggers for the package.
