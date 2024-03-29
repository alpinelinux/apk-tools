apk-world(5)

# NAME

*/etc/apk/world* - list of constraints for package selection

# DESCRIPTION

At /etc/apk/world, apk maintains the _world_, that is, a list of constraints
the package selection needs to fulfill.

If you edit this file manually, you should run *apk-fix*(8) to apply the
changes.

# PACKAGE SPECIFICATION

This is a plaintext file with one constraint using dependency notation per line.
Each line has the format: *name{@tag}{[<>~=]version}*.

When modifying existing installation, the installed version is preferred unless
an upgrade is requested or a world constraint or package dependency requires
an alternate version.

To enable selection from a tagged repository, use the format *name@tag*,
e.g. *busybox@edge*. See *apk-repositories*(5) for details on tagged package
repositories. Untagged repositories are also considered for constraints with
a tag. The tag is inherited to all dependencies as an allowed repository.
That is, the dependencies are selected from the tagged repository if the
*name@tag* has a dependency with version constraint requiring a version
available only from the tagged repository. If the dependency can be satisfied
from non-tagged repository it will be preferred.

To constrain the acceptable versions of the package, use the *=*, *<*, *>*,
*>=*, *~*, *>~* or *<~* operators. Respectively, these require the package is
equal to, less than, greater than, greater than or equal, prefix match, greater
than or prefix match, or less than or prefix match to the specified version.
The *~* operator constrains the package to the prefix match of the version number.

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

*busybox~1.6*
	Install any busybox version starting with 1.6. Examples of match:
	1.6, 1.6.0_pre1, 1.6.0, 1.6.5, 1.6.9_p1.

*busybox>~1.6*
	Install a busybox version greater than or prefix match of 1.6.

*busybox<~1.6*
	Install a busybox version less than or prefix match of 1.6.
