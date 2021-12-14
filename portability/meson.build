cc = meson.get_compiler('c')


libportability_src = []


check_functions = [
	['memrchr', 'memrchr.c', 'NEED_MEMRCHR', 'string.h'],
	['strlcpy', 'strlcpy.c', 'NEED_STRLCPY', 'string.h'],
]


foreach f : check_functions
	if not cc.has_function(f.get(0), prefix: '#include <' + f.get(3) + '>', args: ['-D_GNU_SOURCE']) or not cc.has_header_symbol(f.get(3), f.get(0), args: ['-D_GNU_SOURCE'])
		add_project_arguments('-D' + f.get(2), language: 'c')
		libportability_src += [f.get(1)]
	endif
endforeach


if libportability_src.length() > 0
	libportability = static_library(
		'portability',
		libportability_src,
		dependencies: static_deps,
	)

	libportability_dep = declare_dependency(
		link_whole: libportability,
		include_directories: include_directories('.'),
	)
else
	libportability_dep = declare_dependency(
		include_directories: include_directories('.'),
	)
endif
