project(
	'apk-tools',
	['c'],
	default_options : ['c_std=gnu11', 'optimization=2', 'warning_level=1'],
	version: run_command('./get-version.sh', check: true).stdout().strip(),
	meson_version: '>=0.64'
)
so_version = run_command('cat', 'VERSION', check: true).stdout().strip().split()[0]

pkgc = import('pkgconfig')

apk_confdir = get_option('sysconfdir') / 'apk'
apk_libdir = get_option('libdir')

lua_name = 'lua' + get_option('lua_version')
lua_bin_name = get_option('lua_bin')
lua_pc_name = get_option('lua_pc')

lua_bin = find_program(lua_bin_name != '' ? lua_bin_name : lua_name, required: get_option('help'), native: true)
lua_dep = dependency(lua_pc_name != '' ? lua_pc_name : lua_name, required: get_option('lua'))

python_dep = dependency('python3', required: get_option('python'))
scdoc_dep = dependency('scdoc', version: '>=1.10', required: get_option('docs'), native: true)
zlib_dep = dependency('zlib')
libzstd_dep = dependency('libzstd', required: get_option('zstd'))

if get_option('crypto_backend') == 'openssl'
	crypto_dep = dependency('openssl')
elif get_option('crypto_backend') == 'mbedtls'
	crypto_dep = [ dependency('mbedtls'), dependency('mbedcrypto') ]
endif

apk_deps = [ crypto_dep, zlib_dep, libzstd_dep ]

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
if(lua_dep.found())
	subdir('lua')
endif
if(python_dep.found())
	subdir('python')
endif
subdir('test')
