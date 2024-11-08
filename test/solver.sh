#!/bin/sh

update_repo() {
	local repo="$1"
	if [ ! -f "$repo.adb" -o "$repo.repo" -nt "$repo.adb" ]; then
		tar czf "$repo.adb" --transform "flags=r;s|$repo|APKINDEX|" "$repo"
	fi
}

run_test() {
	local test="$1"

	tmproot=$(mktemp -d -p /tmp apktest.$test.XXXXXXXX)
	mkdir -p "$tmproot/etc/apk/cache" \
		"$tmproot/lib/apk/db" \
		"$tmproot/var/log" \
		"$tmproot/data/src"
	touch "$tmproot/etc/apk/world"
	touch "$tmproot/lib/apk/db/installed"
	ln -sf /dev/null "$tmproot/var/log/apk.log"

	local args="" repo run_found
	exec 4> /dev/null
	while IFS="" read ln; do
		case "$ln" in
		"@ARGS "*)
			args="$args ${ln#* }"
			run_found=yes
			;;
		"@WORLD "*)
			for dep in ${ln#* }; do
				echo "$dep"
			done > "$tmproot/etc/apk/world"
			;;
		"@INSTALLED "*)
			ln -snf "$PWD/${ln#* }" "$tmproot/lib/apk/db/installed"
			;;
		"@REPO @"*)
			tag="${ln#* }"
			repo="${tag#* }"
			tag="${tag% *}"
			update_repo "$repo"
			echo "$tag file://localhost/$PWD/$repo.adb" >> "$tmproot"/etc/apk/repositories
			;;
		"@REPO "*)
			repo="${ln#* }"
			update_repo "$repo"
			echo "file://localhost/$PWD/$repo.adb" >> "$tmproot"/etc/apk/repositories
			;;
		"@CACHE "*)
			ln -snf "$PWD/${ln#* }" "$tmproot/etc/apk/cache/installed"
			;;
		"@EXPECT")
			exec 4> "$tmproot/data/expected"
			;;
		"@"*)
			echo "$test: invalid spec: $ln"
			run_found=""
			break
			;;
		*)
			echo "$ln" >&4
			;;
		esac
	done < "$test"
	exec 4> /dev/null

	if [ "$run_found" = "yes" ]; then
		$APK_TEST --allow-untrusted --simulate --root "$tmproot" $args > "$tmproot/data/output" 2>&1

		if ! cmp "$tmproot/data/output" "$tmproot/data/expected" > /dev/null 2>&1; then
			fail=$((fail+1))
			echo "FAIL: $test"
			diff -ru "$tmproot/data/expected" "$tmproot/data/output"
		else
			pass=$((pass+1))
		fi
	else
		fail=$((fail+1))
	fi

	rm -rf "$tmproot"
}

APK_TEST="$VALGRIND ../src/apk"
TEST_TO_RUN="$@"

fail=0
pass=0
for test in ${TEST_TO_RUN:-*.test}; do
	run_test "$test"
done

total=$((fail+pass))
if [ "$fail" != "0" ]; then
	echo "FAIL: $fail of $total test cases failed"
else
	echo "OK: all $total solver test cases passed"
fi
exit $fail
