#!/bin/sh

# shellcheck disable=SC2016 # no expansion for pkgname-spec

. "$(dirname "$0")"/../testlib.sh

setup_apkroot
APK="$APK --allow-untrusted --no-interactive"

$APK mkpkg -I name:test-a -I version:1.0 -o test-a-1.0.apk
$APK mkpkg -I name:test-b -I version:1.0 -o test-b-1.0.apk

$APK mkndx -q -o index.adb test-a-1.0.apk
$APK mkndx -vv -o index2.adb -x index.adb test-a-1.0.apk test-b-1.0.apk > mkndx.log

diff -u mkndx.log - <<EOF || assert "wrong mkndx result"
test-a-1.0.apk: indexed from old index
test-b-1.0.apk: indexed new package
Index has 2 packages (of which 1 are new)
EOF

$APK mkndx --pkgname-spec 'https://test/${name}-${version}.apk' -o index.adb test-a-1.0.apk test-b-1.0.apk
$APK fetch --url --simulate --from none --repository index.adb --pkgname-spec '${name}_${version}.pkg' test-a test-b > fetch.log 2>&1
diff -u fetch.log - <<EOF || assert "wrong fetch result"
https://test/test-a-1.0.apk
https://test/test-b-1.0.apk
EOF

$APK mkndx --pkgname-spec '${name:3}/${name}-${version}.apk' -o index.adb test-a-1.0.apk test-b-1.0.apk
$APK fetch --url --simulate --from none --repository "file://localhost/$PWD/index.adb" --pkgname-spec '${name}_${version}.pkg' test-a test-b > fetch.log 2>&1
diff -u fetch.log - <<EOF || assert "wrong fetch result"
file://localhost/$PWD/tes/test-a-1.0.apk
file://localhost/$PWD/tes/test-b-1.0.apk
EOF

$APK mkndx --pkgname-spec '${name:3}/${name}-${version}.apk' -o index.adb test-a-1.0.apk test-b-1.0.apk
$APK fetch --url --simulate --from none --repository index.adb --pkgname-spec '${name}_${version}.pkg' test-a test-b > fetch.log 2>&1
diff -u fetch.log - <<EOF || assert "wrong fetch result"
./tes/test-a-1.0.apk
./tes/test-b-1.0.apk
EOF
