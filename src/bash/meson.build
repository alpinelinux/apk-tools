generated_bash_completion = custom_target(
	'apk.bash-completion',
	capture: true,
	output: '_apk',
	input: man_files,
	command: [lua_bin, genhelp_script, '--format=bash', '@INPUT@'],
	depend_files: 'gen_bash.lua',
	env: lua_env,
	install: true,
	install_dir: join_paths(get_option('datadir'), 'bash-completion', 'completions')
)
