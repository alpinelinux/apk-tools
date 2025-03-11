man_filenames = [
    'apk.8.scd',
    'apk-adbdump.8.scd',
    'apk-adbgen.8.scd',
    'apk-adbsign.8.scd',
    'apk-add.8.scd',
    'apk-audit.8.scd',
    'apk-cache.5.scd',
    'apk-cache.8.scd',
    'apk-convdb.8.scd',
    'apk-convndx.8.scd',
    'apk-del.8.scd',
    'apk-dot.8.scd',
    'apk-extract.8.scd',
    'apk-fetch.8.scd',
    'apk-fix.8.scd',
    'apk-index.8.scd',
    'apk-info.8.scd',
    'apk-keys.5.scd',
    'apk-list.8.scd',
    'apk-manifest.8.scd',
    'apk-mkndx.8.scd',
    'apk-mkpkg.8.scd',
    'apk-package.5.scd',
    'apk-policy.8.scd',
    'apk-protected_paths.5.scd',
    'apk-query.8.scd',
    'apk-repositories.5.scd',
    'apk-search.8.scd',
    'apk-stats.8.scd',
    'apk-update.8.scd',
    'apk-upgrade.8.scd',
    'apk-v2.5.scd',
    'apk-v3.5.scd',
    'apk-verify.8.scd',
    'apk-version.8.scd',
    'apk-world.5.scd',
]
man_files = files(man_filenames)

if scdoc_dep.found()
    scdoc_prog = find_program(scdoc_dep.get_variable(pkgconfig: 'scdoc'), native: true)
    sh = find_program('sh', native: true)
    mandir = get_option('mandir')

    foreach filename : man_filenames
        topic = '@0@'.format(filename).split('.')[-3].split('/')[-1]
        section = '@0@'.format(filename).split('.')[-2]
        output = '@0@.@1@'.format(topic, section)

        custom_target(
            output,
            input: files(filename),
            capture: true,
            output: output,
            command: [
                sh, '-c', '@0@ < @INPUT@'.format(scdoc_prog.full_path())
            ],
            install: true,
            install_dir: '@0@/man@1@'.format(mandir, section)
        )
    endforeach
endif
