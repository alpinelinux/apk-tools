luaapk_src = [
	'lua-apk.c',
]

luaapk = shared_module(
	'apk',
	luaapk_src,
	dependencies: [
		lua_dep,
		libapk_dep,
		apk_deps,
		libportability_dep.partial_dependency(includes: true),
	],
	install: not subproject,
	install_dir: apk_libdir / 'lua' / get_option('lua_version'),
	name_prefix: '',
	c_args: apk_cargs,
)
