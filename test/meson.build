cur_dir = meson.current_source_dir()
env = environment()
env.set('APK', apk_exe.full_path())

enum_sh = files('enum.sh')
solver_sh = files('solver.sh')

foreach t : run_command(enum_sh, 'shell', check: true).stdout().strip().split(' ')
	test(t, files(cur_dir / t), env: env, priority: 100)
endforeach

foreach t : run_command(enum_sh, 'solver', check: true).stdout().strip().split(' ')
	test(t, solver_sh, args: [ cur_dir / t ], env: env, priority: 10)
endforeach
