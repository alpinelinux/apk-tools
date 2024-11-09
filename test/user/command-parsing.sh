#!/bin/sh

help_output=$(../src/apk version --help 2>/dev/null)
invalid_option_output="$(../src/apk --invalid-option version 2>/dev/null)"
[ "$help_output" == "$invalid_option_output" ]
