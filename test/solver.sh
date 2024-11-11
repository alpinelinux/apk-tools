#!/bin/sh

update_repo() {
	local repo="$1"
	if [ ! -f "$repo.adb" -o "$repo" -nt "$repo.adb" ]; then
		local tmpname="$repo.new.$$"
		tar czf "$tmpname" -P --transform "flags=r;s|$repo|APKINDEX|" "$repo"
		mv "$tmpname" "$repo.adb"
	fi
}

run_test() {
	local test="$1"
	local testdir="$(realpath "$(dirname "$test")")"

	tmproot=$(mktemp -d -p /tmp apktest.$(basename $test).XXXXXXXX)
	[ -d "$tmproot" ] || return 1

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
			ln -snf "${testdir}/${ln#* }" "$tmproot/lib/apk/db/installed"
			;;
		"@REPO @"*)
			tag="${ln#* }"
			repo="${tag#* }"
			tag="${tag% *}"
			update_repo "$testdir/$repo"
			echo "$tag file://localhost/${testdir}/$repo.adb" >> "$tmproot"/etc/apk/repositories
			;;
		"@REPO "*)
			repo="${ln#* }"
			update_repo "$testdir/$repo"
			echo "file://localhost/${testdir}/$repo.adb" >> "$tmproot"/etc/apk/repositories
			;;
		"@CACHE "*)
			ln -snf "${testdir}/${ln#* }" "$tmproot/etc/apk/cache/installed"
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

	retcode=1
	if [ "$run_found" = "yes" ]; then
		$APK --allow-untrusted --simulate --root "$tmproot" $args > "$tmproot/data/output" 2>&1

		if ! cmp "$tmproot/data/output" "$tmproot/data/expected" > /dev/null 2>&1; then
			fail=$((fail+1))
			echo "FAIL: $test"
			diff -ru "$tmproot/data/expected" "$tmproot/data/output"
		else
			retcode=0
		fi
	fi

	rm -rf "$tmproot"
	return $retcode
}

TEST_TO_RUN="$@"

fail=0
pass=0
for test in ${TEST_TO_RUN:-solver/*.test}; do
	if run_test "$test"; then
		pass=$((pass+1))
	else
		fail=$((fail+1))
	fi
done

if [ -z "$TEST_TO_RUN" ]; then
	total=$((fail+pass))
	if [ "$fail" != "0" ]; then
		echo "FAIL: $fail of $total test cases failed"
	else
		echo "OK: all $total solver test cases passed"
	fi
fi
[ "$fail" == 0 ] || exit 1
exit 0
