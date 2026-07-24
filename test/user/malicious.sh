#!/bin/sh

TESTDIR=$(realpath "${TESTDIR:-"$(dirname "$0")"/..}")
. "$TESTDIR"/testlib.sh

require_programs xxd

setup_apkroot
APK="$APK --allow-untrusted --no-interactive"

mkdir -p files/a files/dir===dir
echo hello > files/a/file=file

$APK mkpkg --compression=none -I name:malicious -I version:1.0 -F files -o malicious-1.0.apk

echo hello > files/a/"file	file"
$APK mkpkg --compression=none -I name:malicious -I version:1.0 -F files -o malicious-1.0b.apk && assert "mkpkg filename check failed"

mkdir dest dest-a dest-b
$APK extract malicious-1.0.apk --destination dest || assert "failed to extract"

xxd -p -c100000 malicious-1.0.apk | sed -e 's,6469723d3d3d646972,6469722f2e2f646972,' | xxd -rp > malicious-1.0-a.apk
$APK extract malicious-1.0-a.apk --destination dest-a && assert "malicious check 1 failed"

xxd -p -c100000 malicious-1.0.apk | sed -e 's,66696c653d66696c65,66696c652f66696c65,' | xxd -rp > malicious-1.0-b.apk
$APK extract malicious-1.0-b.apk --destination dest-b && assert "malicious check 2 failed"

exit 0
