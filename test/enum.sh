#!/bin/sh

cd "$(dirname "$0")"
case "$1" in
solver)
	echo solver/*.test
	;;
shell)
	echo user/*.sh
	;;
esac
