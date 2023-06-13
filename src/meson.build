libapk_so_version = '2.99.0'
libapk_src = [
	'adb.c',
	'adb_comp.c',
	'adb_walk_adb.c',
	'adb_walk_genadb.c',
	'adb_walk_gentext.c',
	'adb_walk_text.c',
	'apk_adb.c',
	'atom.c',
	'blob.c',
	'commit.c',
	'common.c',
	'context.c',
	'crypto_openssl.c',
	'database.c',
	'extract_v2.c',
	'extract_v3.c',
	'fs_fsys.c',
	'fs_uvol.c',
	'hash.c',
	'io.c',
	'io_url.c',
	'io_gunzip.c',
	'io_zstd.c',
	'package.c',
	'pathbuilder.c',
	'print.c',
	'solver.c',
	'tar.c',
	'trust.c',
	'version.c',
]

libapk_headers = [
	'apk_applet.h',
	'apk_atom.h',
	'apk_blob.h',
	'apk_crypto.h',
	'apk_database.h',
	'apk_defines.h',
	'apk_extract.h',
	'apk_fs.h',
	'apk_hash.h',
	'apk_io.h',
	'apk_openssl.h',
	'apk_package.h',
	'apk_pathbuilder.h',
	'apk_print.h',
	'apk_provider_data.h',
	'apk_solver_data.h',
	'apk_solver.h',
	'apk_tar.h',
	'apk_version.h',
]

apk_src = [
	'apk.c',
	'app_adbdump.c',
	'app_adbsign.c',
	'app_add.c',
	'app_audit.c',
	'app_cache.c',
	'app_convdb.c',
	'app_convndx.c',
	'app_del.c',
	'app_dot.c',
	'app_extract.c',
	'app_fetch.c',
	'app_fix.c',
	'app_index.c',
	'app_info.c',
	'app_list.c',
	'app_manifest.c',
	'app_mkndx.c',
	'app_mkpkg.c',
	'app_policy.c',
	'app_update.c',
	'app_upgrade.c',
	'app_search.c',
	'app_stats.c',
	'app_verify.c',
	'app_version.c',
	'app_vertest.c',
	'applet.c',
]

if lua_bin.found()
	genhelp_script = files('genhelp.lua')
	genhelp_args = [lua_bin, genhelp_script, '@INPUT@']

	if not get_option('compressed-help')
		genhelp_args += ['--no-zlib']
	endif

	generated_help = custom_target(
		'help.h',
		capture: true,
		output: 'help.h',
		input: man_files,
		command: genhelp_args,
	)
else
	generated_help = custom_target(
		'help.h',
		capture: true,
		output: 'help.h',
		command: ['echo', '#define NO_HELP'],
	)
endif

apk_src += [ generated_help ]

apk_cargs = [
	'-DAPK_VERSION="' + meson.project_version() + '"',
	'-D_ATFILE_SOURCE',
]

apk_arch_prefix = get_option('arch_prefix')
if apk_arch_prefix != ''
	apk_cargs += ['-DAPK_ARCH_PREFIX="@0@"'.format(apk_arch_prefix)]
endif

libapk_shared = shared_library(
	'apk',
	libapk_src,
	version: libapk_so_version,
	install: not subproject,
	dependencies: [
		libfetch_dep,
		libportability_dep,
		shared_deps,
	],
	c_args: apk_cargs,
)

libapk_static = static_library(
	'apk',
	libapk_src,
	install: not subproject,
	dependencies: [
		libfetch_dep,
		libportability_dep,
		static_deps,
	],
	c_args: [apk_cargs, '-DOPENSSL_NO_ENGINE'],
)

libapk_dep = declare_dependency(
	link_with: libapk_shared,
)

if not subproject
	pkgc.generate(
		libapk_shared,
		name: 'apk',
		version: libapk_so_version,
	)

	install_headers(
		libapk_headers,
		subdir: 'apk',
	)
endif

if(lua_dep.found())
	luaapk_src = [
		'lua-apk.c',
	]

	libluaapk = library(
		'luaapk',
		luaapk_src,
		dependencies: [
			lua_dep,
			libapk_dep,
			shared_deps,
			libportability_dep.partial_dependency(includes: true),
		],
		install: true,
		install_dir: lua_dep.get_pkgconfig_variable('libdir'),
		c_args: apk_cargs,
	)
endif

apk_exe = executable(
	'apk',
	apk_src,
	install: not subproject,
	dependencies: [
		libapk_dep,
		shared_deps,
		libfetch_dep.partial_dependency(includes: true),
		libportability_dep.partial_dependency(includes: true),
	],
	c_args: apk_cargs,
)

if get_option('static_apk')
	apk_static_exe = executable(
		'apk.static',
		apk_src,
		install: not subproject,
		dependencies: [
			static_deps,
			libfetch_dep.partial_dependency(includes: true),
			libportability_dep.partial_dependency(includes: true),
		],
		link_with: libapk_static,
		c_args: [apk_cargs, '-DOPENSSL_NO_ENGINE'],
		link_args: '-static',
	)
endif
