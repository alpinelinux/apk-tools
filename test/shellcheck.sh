#!/bin/sh

SHELL="${1:-bash}"

err=0
for path in . user alpine; do
	# SC2001 "See if you can use ${variable//search/replace} instead" on bash conflicts with dash
	(cd "${SRCDIR:-.}/$path"; shellcheck -x -e SC2001 -s "$SHELL" -- *.sh) || err=1
done
exit $err
