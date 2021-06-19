apk-audit(8)

# NAME

apk audit - audit directories for changes

# SYNOPSIS

*apk audit* [<_options_>...] _directories_...

# DESCRIPTION

*apk audit* audits the system or specified directories for changes compared to
the package database.

The audit can be done against configuration files only (--backup) to generate
list of files needed to be stored in the overlay in run-from-tmps configuration.
Alternatively, it can audit all installed files (--system) to e.g. detect
unauthorized modifications of system files.

By default, the output format is one file per line, for each modified file.
A character is printed indicating the change detected, followed by a space,
then the affected path. The changes detected are:

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

*--backup*
	Audit configuration files only (default). The list of files to be
	audited is generated from the masks in protected_paths.d.

*--check-permissions*
	Check file permissions too. Namely, the uid, gid and file mode will
	be checked in addition to the file content.

*--packages*
	Print only the packages with changed files. Instead of the full output
	each modification, the set of packages with at least one modified file
	is printed.

	To repair all packages with modified files, one could use:
		apk audit --packages -q | xargs apk fix

*--system*
	Audit all system files. All files provided by packages are verified
	for integrity with the exception of configuration files (listed in
	protected_paths.d). This is useful detecting unauthorized file changes.

*-r, --recursive*
	Descend into directories and audit them as well.
