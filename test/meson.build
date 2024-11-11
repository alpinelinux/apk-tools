cur_dir = meson.current_source_dir()
env = environment()
env.set('APK', apk_exe.full_path())

enum_sh = files('enum.sh')
solver_sh = files('solver.sh')

subdir('unit')

foreach t : run_command(enum_sh, 'shell', check: true).stdout().strip().split(' ')
	test(t, files(cur_dir / t), suite: 'shell', depends: apk_exe, env: env, priority: 100)
endforeach

foreach t : run_command(enum_sh, 'solver', check: true).stdout().strip().split(' ')
	test(t, solver_sh, suite: 'solver', args: [ cur_dir / t ], depends: apk_exe, env: env, priority: 10)
endforeach
