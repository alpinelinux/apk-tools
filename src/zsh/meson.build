generated_zsh_completion = custom_target(
	'apk.zsh-completion',
	capture: true,
	output: '_apk',
	input: man_files,
	command: [lua_bin, genhelp_script, '--format=zsh', '@INPUT@'],
	depend_files: 'gen_zsh.lua',
	env: lua_env,
	install: true,
	install_dir: join_paths(get_option('datadir'), 'zsh', 'site-functions')
)
