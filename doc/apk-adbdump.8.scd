apk-adbdump(8)

# NAME

apk adbdump - dump v3 files in textual representation

# SYNOPSIS

*apk adbdump* _files_...

# DESCRIPTION

*apk adbdump* will dump the metadata portion of given _files_ (packages,
indexes, installeddb) to its textual representation.

The output is YAML "like" (see BUGS) output which can be used to inspect
the metadata. *apk adbgen*(8) can convert the textual representation back
to the binary format.

# OPTIONS

*apk adbdump* does not support any specific options. See *apk*(8) for global
options.

# BUGS

YAML compliant quoting is not impemented correctly at this time.

# SEE ALSO

*apk-adbgen*(8), *apk-package*(5), *apk-v3*(5)
