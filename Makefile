##
# Building apk-tools

-include config.mk

PACKAGE := apk-tools
VERSION := 2.14.10
SO_VERSION := $(VERSION)

export VERSION SO_VERSION

##
# Default directories

DESTDIR		:=
SBINDIR		:= /sbin
LIBDIR		:= /lib
CONFDIR		:= /etc/apk
MANDIR		:= /usr/share/man
DOCDIR		:= /usr/share/doc/apk
INCLUDEDIR	:= /usr/include
PKGCONFIGDIR	:= /usr/lib/pkgconfig

export DESTDIR SBINDIR LIBDIR CONFDIR MANDIR DOCDIR INCLUDEDIR PKGCONFIGDIR

##
# Top-level subdirs

subdirs		:= libfetch/ src/ doc/

##
# Include all rules and stuff

include Make.rules

##
# Top-level targets

install:
	$(INSTALLDIR) $(DESTDIR)$(DOCDIR)
	$(INSTALL) README.md $(DESTDIR)$(DOCDIR)

check test: FORCE
	$(Q)$(MAKE) TEST=y compile
	$(Q)$(MAKE) -C test

static:
	$(Q)$(MAKE) STATIC=y

tag: check
	git commit . -m "apk-tools-$(VERSION)"
	git tag -s v$(VERSION) -m "apk-tools-$(VERSION)"

src/: libfetch/
