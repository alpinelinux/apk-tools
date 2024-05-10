project(
	'apk-tools',
	['c'],
	default_options : ['c_std=gnu11', 'optimization=2', 'warning_level=1'],
	version: run_command('./get-version.sh', check: true).stdout().strip(),
	meson_version: '>=0.55'
)
pkgc = import('pkgconfig')

apk_confdir = get_option('sysconfdir') / 'apk'
apk_libdir = get_option('libdir')

lua_bin = find_program('lua' + get_option('lua_version'), required: get_option('help'))
lua_dep = dependency('lua' + get_option('lua_version'), required: get_option('lua'))
scdoc_dep = dependency('scdoc', version: '>=1.10', required: get_option('docs'))
zlib_dep = dependency('zlib')
zlib_static_dep = dependency('zlib', static: true)
libzstd_dep = dependency('libzstd', required: get_option('zstd'))
libzstd_static_dep = dependency('libzstd', required: get_option('zstd'), static: true)

if get_option('crypto_backend') == 'openssl'
	crypto_dep = dependency('openssl')
	crypto_static_dep = dependency('openssl', static: true)
elif get_option('crypto_backend') == 'mbedtls'
	crypto_dep = [ dependency('mbedtls'), dependency('mbedcrypto') ]
	crypto_static_dep = [ dependency('mbedtls', static: true), dependency('mbedcrypto', static: true) ]
endif

shared_deps = [ crypto_dep, zlib_dep, libzstd_dep ]
static_deps = [ crypto_static_dep, zlib_static_dep, libzstd_static_dep ]

add_project_arguments('-D_GNU_SOURCE', language: 'c')

# Needed for 64-bit off_t and friends on glibc.
add_project_arguments('-D_FILE_OFFSET_BITS=64', language: 'c')

# If we're a subproject we only want the static lib and not files
subproject = meson.is_subproject()

subdir('doc')
subdir('portability')
if get_option('url_backend') == 'libfetch'
	subdir('libfetch')
else
	libfetch_dep = dependency('', required: false)
endif
subdir('src')
subdir('tests')
