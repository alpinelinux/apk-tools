#!/bin/sh

: ${APK=apk} ${SRC=.}
T_MODE="$1"
shift 1
case "$T_MODE" in
--all)
	t_case() { true; }
	t_end() { exit 0; }
	set -e -o pipefail
	;;
--list)
	t_case() { echo "$@"; false; }
	t_end() { exit 0; }
	;;
--test)
	T_WANTED_CASE="$1"
	shift
	t_case() { [ "$@" = "$T_WANTED_CASE" ]; }
	t_end() { exit 0; }
	set -e -o pipefail
	;;
*)
	echo "invalid mode"
	exit 1
	;;
esac
