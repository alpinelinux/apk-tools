#!/bin/sh

TESTDIR=$(realpath "${TESTDIR:-"$(dirname "$0")"/..}")
. "$TESTDIR"/testlib.sh

help_output=$($APK version --help 2>/dev/null) || true
invalid_option_output="$($APK --invalid-option version 2>/dev/null)" || true
[ "$help_output" = "$invalid_option_output" ] || assert "wrong help"
