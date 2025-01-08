#!/bin/sh

TESTDIR=$(realpath "${TESTDIR:-"$(dirname "$0")"/..}")
. "$TESTDIR"/testlib.sh

create_pkg() {
	local ver="$1"
	local pkgdir="files/"a-${ver}""

	mkdir -p "$pkgdir"/etc "$pkgdir"/data
	echo "test file v${ver}" > "$pkgdir"/etc/test
	echo "data file v${ver}" > "$pkgdir"/data/test

	$APK mkpkg -I name:test-a -I "version:${ver}" -F "$pkgdir" -o "test-a-${ver}.apk"
}

setup_apkroot
APK="$APK --allow-untrusted --no-interactive"

create_pkg 1.0
create_pkg 2.0
create_pkg 3.0

$APK add --initdb $TEST_USERMODE test-a-1.0.apk

echo "modified" > "$TEST_ROOT"/etc/test
echo "modified" > "$TEST_ROOT"/data/test

$APK add test-a-2.0.apk
cd "$TEST_ROOT"
[ -e etc/test.apk-new ] || assert ".apk-new not found"
[ "$(cat etc/test)" = "modified" ] || assert "etc updated unexpectedly"
[ "$(cat data/test)" = "data file v2.0" ] || assert "data not update"
cd -

rm -rf "$TEST_ROOT"/data/test
mkdir -p "$TEST_ROOT"/data/test
$APK add test-a-3.0.apk && assert "succeeded unexpectedly"
glob_one "$TEST_ROOT"/data/.apk.* && assert "unexpected temporary file found"

exit 0
