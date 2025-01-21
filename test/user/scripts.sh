#!/bin/sh

TESTDIR=$(realpath "${TESTDIR:-"$(dirname "$0")"/..}")
. "$TESTDIR"/testlib.sh

setup_apkroot
APK="$APK --allow-untrusted --no-interactive --force-no-chroot"

cat <<EOF > pre.sh
#!/bin/sh
echo Hello from pre-install
echo Error hello >&2
EOF
cat <<EOF > post.sh
#!/bin/sh
echo Hello from post-install
echo Error hello >&2
EOF
$APK mkpkg -I name:scripts -I version:1.0 -s pre-install:pre.sh -s post-install:post.sh -o scripts-1.0.apk

$APK add --initdb $TEST_USERMODE scripts-1.0.apk > apk-stdout.log 2> apk-stderr.log
diff -u - apk-stdout.log <<EOF || assert "wrong scripts result"
(1/1) Installing scripts (1.0)
scripts-1.0.pre-install: Executing script...
scripts-1.0.pre-install: Hello from pre-install
scripts-1.0.post-install: Executing script...
scripts-1.0.post-install: Hello from post-install
OK: 0 MiB in 1 packages
EOF

diff -u - apk-stderr.log <<EOF || assert "wrong scripts result"
scripts-1.0.pre-install: Error hello
scripts-1.0.post-install: Error hello
EOF
