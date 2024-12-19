subdir('unit')

enum_sh = find_program('enum.sh', required: get_option('tests'))
solver_sh = find_program('solver.sh', required: get_option('tests'))
shellcheck_sh = find_program('shellcheck.sh', required: get_option('tests'))
shellcheck = find_program('shellcheck', required: false)

cur_dir = meson.current_source_dir()
env = environment()
env.set('SRCDIR', cur_dir)
env.set('APK', apk_exe.full_path())

if shellcheck_sh.found() and shellcheck.found()
	foreach shell : [ 'bash', 'dash', 'busybox' ]
		test(shell, shellcheck_sh, suite: 'shellcheck', args: [ shell ], env: env, priority: 1000)
	endforeach
endif

if enum_sh.found() and solver_sh.found()
	foreach t : run_command(enum_sh, 'shell', check: true).stdout().strip().split(' ')
		test(t, files(cur_dir / t), suite: 'shell', depends: apk_exe, env: env, priority: 100)
	endforeach

	foreach t : run_command(enum_sh, 'solver', check: true).stdout().strip().split(' ')
		test(t, solver_sh, suite: 'solver', args: [ cur_dir / t ], depends: apk_exe, env: env, priority: 10)
	endforeach
endif
