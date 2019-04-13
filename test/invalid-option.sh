#!/bin/sh

fail=0

help_output=$(../src/apk version --help)
invalid_option_output="$(../src/apk --invalid-option version)"
if [ "$help_output" != "$invalid_option_output" ] ; then
    echo "FAIL: invalid option"
    fail=$(($fail+1))
fi

if [ "$fail" == "0" ]; then
    echo "OK: invalid option checking works"
fi

exit $fail
