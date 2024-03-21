env = environment()
env.set('APK', apk_exe.full_path())
env.set('SRC', meson.current_source_dir())

test_program = find_program('test-basic.sh')
test_list = run_command(test_program, '--list', check: true).stdout().split('\n')

foreach test : test_list
	test = test.strip()
	if test != ''
		test(test, test_program, args: ['--test', test], env: env)
	endif
endforeach
