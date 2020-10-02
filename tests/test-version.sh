#!/bin/sh
APK=${1:-apk}
sed 's/[[:blank:]]*#.*//g' < version.data | tr '\n' '\0' | xargs -0 $APK vertest
