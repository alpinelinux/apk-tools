apk-version(8)

# NAME

apk version - compare package versions

# SYNOPSIS

*apk version* [<_options_>...] [_packages_...]

*apk version* -c _versions_...

*apk version* -t _version1_ _version2_

*apk version* -I

# DESCRIPTION

*apk version* compares the versions of installed packages against package
versions available from repositories (see *apk-repositories*(5)). It can also
be used to validate and compare version strings.

In default mode, if no packages are specified, all installed packages are
considered. Otherwise, the comparison is limited to the explicitly listed
packages. A summary is printed on stdout, with the difference between package
versions being represented as *>*, *=*, or *<*.

*apk version -c* tests the specified version string(s) for validity and prints
a list of _invalid_ version strings. If all version strings are valid, nothing
is printed and *apk version* exits with status code zero. If one or more
version strings are invalid, the exit code is nonzero.

*apk version -t* accepts two arbitrary version strings and compares them
without consulting the database, then prints the result as *>*, *=*, or *<*.

*apk version -I* prints the versions and descriptions of each repository's
index. See *apk-repositories*(5) for more information.

# OPTIONS

These options only apply when checking installed package versions against
packages available from the repositories (when neither *-c*, *-t*, nor *-I* are
specified).

*-a*
	Consider packages from all repository tags.

*-l* _operand_
	Limit to packages with output matching given _operand_. The _operand_
	can be specified as any combination of *>*, *=*, and *<*.
