PKG_CONFIG		?= pkg-config
LUA			?= $(firstword $(wildcard /usr/bin/lua5.3 /usr/bin/lua5.2))

ifeq ($(LUA),no)
LUAAPK			?= no
else ifneq ($(LUA),)
LUAAPK			?= yes
else
$(error Lua interpreter not found. Please specify LUA interpreter, or use LUA=no to build without help.)
endif

OPENSSL_CFLAGS		:= $(shell $(PKG_CONFIG) --cflags openssl)
OPENSSL_LIBS		:= $(shell $(PKG_CONFIG) --libs openssl)

ZLIB_CFLAGS		:= $(shell $(PKG_CONFIG) --cflags zlib)
ZLIB_LIBS		:= $(shell $(PKG_CONFIG) --libs zlib)

# Dynamic library
libapk_soname		:= 2.99.0
libapk_so		:= $(obj)/libapk.so.$(libapk_soname)
libapk.so.$(libapk_soname)-objs := \
	adb.o adb_comp.o adb_walk_adb.o adb_walk_genadb.o adb_walk_gentext.o adb_walk_text.o apk_adb.o \
	atom.o blob.o commit.o common.o context.o crypto_openssl.o database.o hash.o \
	extract_v2.o extract_v3.o fs_fsys.o fs_uvol.o io.o io_gunzip.o io_url.o tar.o \
	package.o pathbuilder.o print.o solver.o trust.o version.o

libapk.so.$(libapk_soname)-libs := libfetch/libfetch.a

shlibs-y		+= libapk.so.$(libapk_soname)
LDFLAGS_libapk.so.$(libapk_soname) += -Wl,-soname,libapk.so.$(libapk_soname)

install-libapk_so	:= $(INSTALLDIR) $(DESTDIR)$(LIBDIR) && \
			   $(INSTALL) $(libapk_so) $(DESTDIR)$(LIBDIR) && \
			   $(LN) libapk.so.$(libapk_soname) $(DESTDIR)$(LIBDIR)/libapk.so

# Static library
libapk.a-objs		:= $(libapk.so.$(libapk_soname)-objs)
libapk.a-libs		:= $(libapk.so.$(libapk_soname)-libs)

libs-y			+= libapk.a
libapk_a		:= $(obj)/libapk.a

install-libapk_a	:= $(INSTALLDIR) $(DESTDIR)$(LIBDIR) && \
			   $(INSTALL) $(libapk_a) $(DESTDIR)$(LIBDIR)
apk-static-libs		:= $(libapk.a-libs) $(obj)/libapk.a

# Lua module
ifeq ($(LUAAPK),yes)
LUA_VERSION		?= 5.3
LUA_PC			?= lua$(LUA_VERSION)
LUA_LIBDIR		?= /usr/lib/lua/$(LUA_VERSION)
shlibs-y		+= apk.so
apk.so-objs		:= lua-apk.o
CFLAGS_lua-apk.o	:= -DAPK_VERSION=\"$(FULL_VERSION)\" \
			   $(shell $(PKG_CONFIG) $(LUA_PC) --cflags)
apklua_so		:= $(obj)/apk.so
install-apklua_so	:= $(INSTALLDIR) $(DESTDIR)$(LUA_LIBDIR) && \
			   $(INSTALL) $(apklua_so) $(DESTDIR)$(LUA_LIBDIR)
endif

# Apk utility
progs-y			+= apk
apk-objs		:= \
	apk.o app_adbdump.o app_adbsign.o app_add.o app_audit.o app_cache.o \
	app_convdb.o app_convndx.o app_del.o app_dot.o app_extract.o app_fetch.o \
	app_fix.o app_index.o app_info.o app_list.o app_manifest.o app_mkndx.o \
	app_mkpkg.o app_policy.o app_update.o app_upgrade.o app_search.o \
	app_stats.o app_verify.o app_version.o app_vertest.o applet.o

ifeq ($(ADB),y)
libapk.so.$(libapk_soname)-objs += apk_adb.o
apk-objs		+= app_adbdump.o app_adbsign.o app_mkndx.o \
			   app_convdb.o app_convndx.o
endif

LIBS_apk		:= -lapk
LIBS_apk-test		:= -lapk
LIBS_apk.so		:= -L$(obj) -lapk

CFLAGS_ALL		+= -D_ATFILE_SOURCE -Ilibfetch -Iportability
CFLAGS_apk.o		:= -DAPK_VERSION=\"$(FULL_VERSION)\"
CFLAGS_apk-static.o	:= -DAPK_VERSION=\"$(FULL_VERSION)\" -DOPENSSL_NO_ENGINE
CFLAGS_apk-test.o	:= -DAPK_VERSION=\"$(FULL_VERSION)\" -DOPENSSL_NO_ENGINE -DTEST_MODE

progs-$(STATIC)		+= apk.static
apk.static-objs		:= $(filter-out apk.o,$(apk-objs)) apk-static.o
apk.static-libs		:= $(apk-static-libs)
LDFLAGS_apk.static	:= -static
LIBS_apk.static		:= -Wl,--as-needed -ldl -Wl,--no-as-needed
LDFLAGS_apk		+= -L$(obj)
LDFLAGS_apk-test	+= -L$(obj)

CFLAGS_ALL		+= $(OPENSSL_CFLAGS) $(ZLIB_CFLAGS)
LIBS			:= -Wl,--as-needed \
				$(OPENSSL_LIBS) $(ZLIB_LIBS) \
			   -Wl,--no-as-needed

# Help generation
quiet_cmd_genhelp = GENHELP $@
ifneq ($(LUA),no)
      cmd_genhelp = $(LUA) $(src)/genhelp.lua $(filter %.scd, $^) > $@
else
      cmd_genhelp = echo \\\#define NO_HELP > $@
endif

$(obj)/help.h: $(src)/genhelp.lua $(wildcard doc/apk*.8.scd) FORCE
	$(call if_changed,genhelp)

CFLAGS_help.o		:= -I$(obj)

generate-y		+= help.h

# Test build
ifeq ($(TEST),y)
progs-y			+= apk-test
apk-test-objs		:= apk-test.o $(filter-out apk.o, $(apk-objs))
endif

$(obj)/apk: $(libapk_so)

$(obj)/apk-test: $(libapk_so)

$(obj)/apk.so: $(libapk_so)

generate-y	+= libapk.so

$(obj)/libapk.so:
	$(LN) libapk.so.$(libapk_soname) $(obj)/libapk.so

generate-y	+= apk.pc

install: $(obj)/apk $(libapk_so) $(libapk_a) $(apklua_so)
	$(INSTALLDIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL) $(obj)/apk $(DESTDIR)$(SBINDIR)
	$(install-libapk_so)
	$(install-libapk_a)
	$(install-apklua_so)
	$(INSTALLDIR) $(DESTDIR)$(INCLUDEDIR)/apk
	$(INSTALL) -m644 src/*.h $(DESTDIR)$(INCLUDEDIR)/apk
	$(INSTALLDIR) $(DESTDIR)$(PKGCONFIGDIR)
	$(INSTALL) -m644 $(obj)/apk.pc $(DESTDIR)$(PKGCONFIGDIR)

