#!/bin/sh

set -e

assert() {
	echo "$*"
	exit 1
}

glob_one() {
	for a in $@; do echo "$a"; done
}

setup_apkroot() {
	TEST_USERMODE=""
	[ "$(id -u)" == 0 ] || TEST_USERMODE="--usermode"

	TEST_ROOT=$(mktemp -d -p /tmp apktest.XXXXXXXX)
	[ -d "$TEST_ROOT" ] || return 1

	trap "rm -rf -- '$TEST_ROOT'" EXIT
	APK="$APK --root $TEST_ROOT"

	mkdir -p "$TEST_ROOT/etc/apk/cache" \
		"$TEST_ROOT/usr/lib/apk/db" \
		"$TEST_ROOT/tmp" \
		"$TEST_ROOT/var/log"

	touch "$TEST_ROOT/etc/apk/world"
	touch "$TEST_ROOT/usr/lib/apk/db/installed"
	ln -sf /dev/null "$TEST_ROOT/var/log/apk.log"
	cd "$TEST_ROOT/tmp"
}

[ -x "$APK" ] || assert "APK environment variable not set"
