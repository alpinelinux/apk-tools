if lua_bin.found()
	generated_help = custom_target(
		'help.h',
		capture: true,
		output: 'help.h',
		input: man_files,
		command: [lua_bin, genhelp_script, '@INPUT@'],
		depend_files: 'gen_help.lua',
		env: lua_env,
	)
else
	generated_help = custom_target(
		'help.h',
		capture: true,
		output: 'help.h',
		command: ['echo', '#define NO_HELP'],
	)
endif
