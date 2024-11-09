-include conf.mk

.PHONY:

APK		?= ../src/apk
LD_LIBRARY_PATH	?= ../src

export APK LD_LIBRARY_PATH

all: tests

test tests check:
	@echo "== Testing `$(APK) --version` =="
	@for i in $(wildcard user/*.sh solver.sh); do \
		./$$i || { echo "FAIL: $$i"; exit 1; }; \
		echo "OK: $$i"; \
	done

