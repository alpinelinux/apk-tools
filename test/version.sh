#!/bin/sh

../src/apk vertest < version.data
fail=$?

if [ "$fail" = "0" ]; then
	echo "OK: version checking works"
	exit 0
fi

echo "FAIL: $fail version checks failed"
exit 1
