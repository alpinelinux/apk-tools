libapk_src = [
    'blob.c',
    'commit.c',
    'common.c',
    'database.c',
    'hash.c',
    'io.c',
    'io_archive.c',
    'io_url.c',
    'io_gunzip.c',
    'package.c',
    'print.c',
    'solver.c',
    'version.c',
]

libapk_headers = [
    'apk_applet.h',
    'apk_archive.h',
    'apk_blob.h',
    'apk_database.h',
    'apk_defines.h',
    'apk_hash.h',
    'apk_io.h',
    'apk_openssl.h',
    'apk_package.h',
    'apk_print.h',
    'apk_provider_data.h',
    'apk_solver_data.h',
    'apk_solver.h',
    'apk_version.h',
]

apk_src = [
    'apk.c',
    'app_add.c',
    'app_audit.c',
    'app_cache.c',
    'app_del.c',
    'app_dot.c',
    'app_fetch.c',
    'app_fix.c',
    'app_index.c',
    'app_info.c',
    'app_list.c',
    'app_manifest.c',
    'app_policy.c',
    'app_update.c',
    'app_upgrade.c',
    'app_search.c',
    'app_stats.c',
    'app_verify.c',
    'app_version.c',
    'help.c',
]

if lua_bin.found()
    genhelp_script = find_program('genhelp.lua')

    generated_help = custom_target(
        'help.h',
        capture: true,
        output: 'help.h',
        input: man_files,
        command: [genhelp_script, '@INPUT@'],
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

libapk = library(
    'apk',
    libapk_src,
    version: meson.project_version(),
    install: true,
    dependencies: [
        libfetch_dep,
        zlib_dep,
        openssl_dep,
    ],
    c_args: apk_cargs,
)

libapk_dep = declare_dependency(
    link_with: libapk,
)

if not subproject
    pkgc.generate(
        libapk,
        name: 'apk',
        version: meson.project_version(),
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
        dependencies: [lua_dep, libapk_dep],
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
        zlib_dep,
        openssl_dep,
        libfetch_dep.partial_dependency(includes: true),
    ],
    c_args: apk_cargs,
)
