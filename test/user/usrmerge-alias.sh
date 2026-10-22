#!/bin/sh

TESTDIR=$(realpath "${TESTDIR:-"$(dirname "$0")"/..}")
. "$TESTDIR"/testlib.sh

# Package 1.0 ships both /bin/tool (symlink) and /usr/bin/tool (regular file).
# Package 2.0 ships only /usr/bin/tool.
# On a usr-merged system /bin is a symlink to usr/bin, so the paths of the
# removed /bin/tool resolve to the very file that 2.0 just installed.
create_pkg() {
	local ver="$1" with_bin_symlink="$2"
	local pkgdir="files/a-${ver}"

	mkdir -p "$pkgdir"/usr/bin
	echo "package $ver" > "$pkgdir"/usr/bin/tool

	if [ "$with_bin_symlink" = "yes" ]; then
		mkdir -p "$pkgdir"/bin
		ln -s ../usr/bin/tool "$pkgdir"/bin/tool
	fi

	$APK mkpkg -I name:test-a -I "version:${ver}" -F "$pkgdir" -o "test-a-${ver}.apk"
}

setup_apkroot
APK="$APK --allow-untrusted --no-interactive"

create_pkg 1.0 yes
create_pkg 2.0 no

$APK add --initdb $TEST_USERMODE test-a-1.0.apk
cd "$TEST_ROOT"
[ -f usr/bin/tool ] || assert "usr/bin/tool not found"
[ -L bin/tool ] || assert "bin/tool symlink not found"
cd - > /dev/null

# manual usr-merge: /bin becomes a symlink to usr/bin
rm "$TEST_ROOT"/bin/tool
rmdir "$TEST_ROOT"/bin
ln -s usr/bin "$TEST_ROOT"/bin

$APK add -vv test-a-2.0.apk
cd "$TEST_ROOT"
[ -f usr/bin/tool ] || assert "usr/bin/tool was removed by the upgrade"
[ "$(cat usr/bin/tool)" = "package 2.0" ] || assert "usr/bin/tool has unexpected content"
[ -e bin/tool ] || assert "bin/tool (via /bin symlink) not found"
[ -L bin ] || assert "/bin is no longer a symlink"
cd - > /dev/null

exit 0
