project(
	'apk-tools',
	['c'],
	default_options : ['c_std=gnu99', 'optimization=2'],
	version: '3.0.0_pre0',
	meson_version: '>=0.52'
)
pkgc = import('pkgconfig')

apk_confdir = get_option('sysconfdir') / 'apk'
apk_libdir = get_option('libdir')

lua_bin = find_program('lua' + get_option('lua_version'), required: get_option('help'))
lua_dep = dependency('lua' + get_option('lua_version'), required: get_option('lua'))
scdoc_dep = dependency('scdoc', version: '>=1.10', required: get_option('docs'))

shared_deps = [
	dependency('zlib'),
	dependency('libzstd'),
	dependency('openssl'),
]

static_deps = [
	dependency('openssl', static: true),
	dependency('zlib', static: true),
	dependency('libzstd', static: true),
]

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
