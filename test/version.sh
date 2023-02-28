#!/bin/sh

fail=0
while read a result b rest ; do
	output="$(../src/apk version -t "$a" "$b")"
	if [ "$output" != "$result" ] ; then
		echo "$a $result $b, but got $output"
		fail=$((fail+1))
	fi
done < version.data

if [ "$fail" == "0" ]; then
	echo "OK: version checking works"
else
	echo "FAIL: $fail version checks failed"
fi

exit $fail

