-include conf.mk

.PHONY:

APK		?= $(realpath ../src/apk)
LD_LIBRARY_PATH	?= $(realpath ../src)

export APK LD_LIBRARY_PATH

all: tests

test tests check:
	@echo "== Testing `$(APK) --version` =="
	@for i in $(wildcard user/*.sh solver.sh); do \
		./$$i >& test.log || { echo "FAIL: $$i"; cat test.log; rm -f test.log; exit 1; }; \
		echo "OK: $$i"; \
	done
	@rm -f test.log

