project(
    'apk-tools',
    ['c'],
    default_options : ['c_std=gnu99'],
    version: '2.10.5',
    meson_version: '>=0.51'
)
pkgc = import('pkgconfig')

apk_confdir = get_option('sysconfdir') / 'apk'
apk_libdir = get_option('libdir')

zlib_dep = dependency('zlib')
openssl_dep = dependency('openssl')
lua_dep = dependency('lua' + get_option('lua_version'), required: get_option('lua'))
scdoc_dep = dependency('scdoc', version: '>=1.10', required: get_option('docs'))

add_project_arguments('-D_GNU_SOURCE', language: 'c')

# If we're a subproject we only want the static lib and not files
subproject = meson.is_subproject()
if get_option('default_library') == 'static'
    add_project_arguments('-DOPENSSL_NO_ENGINE', language: 'c')
endif

subdir('doc')
subdir('libfetch')
subdir('src')