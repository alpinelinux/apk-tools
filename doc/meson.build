man_files = files(
    'apk.8.scd',
    'apk-add.8.scd',
    'apk-audit.8.scd',
    'apk-cache.5.scd',
    'apk-cache.8.scd',
    'apk-del.8.scd',
    'apk-dot.8.scd',
    'apk-fetch.8.scd',
    'apk-fix.8.scd',
    'apk-index.8.scd',
    'apk-info.8.scd',
    'apk-keys.5.scd',
    'apk-list.8.scd',
    'apk-manifest.8.scd',
    'apk-policy.8.scd',
    'apk-repositories.5.scd',
    'apk-stats.8.scd',
    'apk-update.8.scd',
    'apk-upgrade.8.scd',
    'apk-verify.8.scd',
    'apk-version.8.scd',
    'apk-world.5.scd',
)

if scdoc_dep.found()
    scdoc_prog = find_program(scdoc_dep.get_pkgconfig_variable('scdoc'), native: true)
    sh = find_program('sh', native: true)
    mandir = get_option('mandir')

    foreach filename : man_files
        topic = '@0@'.format(filename).split('.')[-3].split('/')[-1]
        section = '@0@'.format(filename).split('.')[-2]
        output = '@0@.@1@'.format(topic, section)

        custom_target(
            output,
            input: filename,
            capture: true,
            output: output,
            command: [
                sh, '-c', '@0@ < @INPUT@'.format(scdoc_prog.path())
            ],
            install: true,
            install_dir: '@0@/man@1@'.format(mandir, section)
        )
    endforeach
endif
