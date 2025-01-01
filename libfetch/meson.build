libfetch_src = [
	'common.c',
	'fetch.c',
	'http.c',
	'openssl-compat.c'
]

libfetch_cargs = [
	'-DCA_CERT_FILE="/' + apk_confdir / 'ca.pem"',
	'-DCA_CRL_FILE="/' + apk_confdir / 'crl.pem"',
	'-DCLIENT_CERT_FILE="/' + apk_confdir / 'cert.pem"',
	'-DCLIENT_KEY_FILE="/' + apk_confdir / 'cert.key"',
]

libfetch = static_library(
	'fetch',
	libfetch_src,
	c_args: libfetch_cargs,
	dependencies: [
		libportability_dep.partial_dependency(compile_args: true, includes: true),
		crypto_dep.partial_dependency(compile_args: true, includes: true)
	],
)

libfetch_dep = declare_dependency(
	link_whole: libfetch,
	include_directories: include_directories('.'),
)
