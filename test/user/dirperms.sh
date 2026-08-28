#!/bin/sh

TESTDIR=$(realpath "${TESTDIR:-"$(dirname "$0")"/..}")
. "$TESTDIR"/testlib.sh

require_programs fakeroot
[ "$FAKEROOTKEY" ] || exec fakeroot "$0" "$@"

setup_apkroot
APK="$APK --allow-untrusted --no-interactive"

mkdir -p files
mkdir -pm7777 files/testdir

$APK mkpkg -I name:stickydir -I version:1.0 -F files -o stickydir-1.0.apk

$APK add --initdb $TEST_USERMODE stickydir-1.0.apk
[ "$(stat -c %a "$TEST_ROOT"/testdir)" == 7777 ] || assert "Wrong directory permissions"
