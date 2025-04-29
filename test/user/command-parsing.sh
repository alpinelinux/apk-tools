#!/bin/sh

TESTDIR=$(realpath "${TESTDIR:-"$(dirname "$0")"/..}")
. "$TESTDIR"/testlib.sh

case "$($APK version --help 2>/dev/null)" in
	apk-tools*', compiled for '*.*) ;;
	*) assert "wrong help" ;;
esac
case "$($APK --unknown-option version 2>&1 >/dev/null)" in
	*'unrecognized option'*'unknown-option'*) ;;
	*) assert "wrong unknown option error" ;;
esac
case "$($APK mkpkg --compression AAA 2>&1 >/dev/null)" in
	*'invalid argument'*'compression'*'AAA'*) ;;
	*) assert "wrong invalid argument error" ;;
esac
