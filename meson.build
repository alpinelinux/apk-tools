project(
	'apk-tools',
	['c'],
	default_options : ['c_std=gnu99', 'optimization=2'],
	version: run_command('./get-version.sh', check: true).stdout().strip(),
	meson_version: '>=0.55'
)
pkgc = import('pkgconfig')

apk_confdir = get_option('sysconfdir') / 'apk'
apk_libdir = get_option('libdir')

lua_bin = find_program('lua' + get_option('lua_version'), required: get_option('help'))
lua_dep = dependency('lua' + get_option('lua_version'), required: get_option('lua'))
scdoc_dep = dependency('scdoc', version: '>=1.10', required: get_option('docs'))
openssl_dep = dependency('openssl')
openssl_static_dep = dependency('openssl', static: true)
zlib_dep = dependency('zlib')
zlib_static_dep = dependency('zlib', static: true)
libzstd_dep = dependency('libzstd', required: get_option('zstd'))
libzstd_static_dep = dependency('libzstd', required: get_option('zstd'), static: true)

shared_deps = [ openssl_dep, zlib_dep, libzstd_dep ]
static_deps = [ openssl_static_dep, zlib_static_dep, libzstd_static_dep ]

add_project_arguments('-D_GNU_SOURCE', language: 'c')

# Needed for 64-bit off_t and friends on glibc.
add_project_arguments('-D_FILE_OFFSET_BITS=64', language: 'c')

# If we're a subproject we only want the static lib and not files
subproject = meson.is_subproject()

subdir('doc')
subdir('portability')
subdir('libfetch')
subdir('src')
subdir('tests')
