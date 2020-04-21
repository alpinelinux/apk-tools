apk-audit(8)

# NAME

apk audit - audit directories for changes

# SYNOPSIS

*apk audit* [<_options_>...] _directories_...

# DESCRIPTION

*apk audit* audits the specified directories for changes from the package
database. By default, the output format is one file per line, for each affected
file. A character is printed indicating the change detected, followed by a
space, then the affected path. The changes detected are:

|[ A
:< File added
|  d
:  Directory added
|  D
:  Directory added (with non-listed files/subdirs)
|  M
:  File metadata changed (uid, gid, or mode)
|  m
:  Directory metadata changed
|  U
:  File contents modified
|  X
:  File deleted
|  x
:  xattrs changed

# OPTIONS

*--check-permissions*
	In addition to checking file contents, check the uid, gid, and file
	mode as well.

*--packages*
	Instead of printing each modified file, print the names and versions of
	the packages which own the affected files.

*--system*
	List all modified configuration files (in protected_paths.d) that need
	to be backed up.

*-r, --recursive*
	Descend into directories and audit them as well.

# AUTHORS

Natanael Copa <ncopa@alpinelinux.org>++
Timo Teräs <timo.teras@iki.fi>
