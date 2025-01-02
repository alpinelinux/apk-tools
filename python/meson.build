py_mod = import('python')
py_inst = py_mod.find_installation('python3')

py_ext = shared_module(
	'apk',
	sources: files('apk_module.c'),
	dependencies: [
		libapk_dep,
		python_dep,
		apk_deps,
		libportability_dep.partial_dependency(includes: true),
	],
	install: true,
	gnu_symbol_visibility: 'hidden',
	name_prefix: '',
	name_suffix: py_inst.get_variable('EXT_SUFFIX').strip('.'),
	c_args: apk_cargs,
	install_dir: py_inst.get_install_dir(),
)
