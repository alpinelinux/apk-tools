#include "apk_test.h"
#include "apk_blob.h"
#include "apk_atom.h"
#include "apk_print.h"

APK_TEST(blob_foreach_word_test) {
	int ch = 'a';
	apk_blob_foreach_word(word, APK_BLOB_STRLIT("a b   c d e  ")) {
		assert_int_equal(word.ptr[0], ch);
		assert_int_equal(word.len, 1);
		ch++;
	}
	assert_int_equal(ch, 'f');
}

APK_TEST(blob_contains) {
	assert_int_equal(-1, apk_blob_contains(APK_BLOB_STRLIT(" foo "), APK_BLOB_STRLIT("bar")));
	assert_int_equal(0, apk_blob_contains(APK_BLOB_STRLIT("bar bar"), APK_BLOB_STRLIT("bar")));
	assert_int_equal(4, apk_blob_contains(APK_BLOB_STRLIT("bar foo"), APK_BLOB_STRLIT("foo")));
}

APK_TEST(blob_split) {
	apk_blob_t l, r;
	assert_int_equal(0, apk_blob_split(APK_BLOB_STRLIT("bar bar"), APK_BLOB_STRLIT("foo"), &l, &r));
	assert_int_equal(1, apk_blob_split(APK_BLOB_STRLIT("bar foo"), APK_BLOB_STRLIT(" "), &l, &r));
	assert_int_equal(0, apk_blob_compare(l, APK_BLOB_STRLIT("bar")));
	assert_int_equal(0, apk_blob_compare(r, APK_BLOB_STRLIT("foo")));
}

APK_TEST(blob_url_sanitize) {
	struct {
		const char *url, *sanitized;
	} tests[] = {
		{ "http://example.com", NULL },
		{ "http://foo@example.com", NULL },
		{ "http://foo:pass@example.com", "http://foo:*@example.com" },
		{ "http://example.com/foo:pass@bar", NULL },
	};
	struct apk_atom_pool atoms;
	apk_atom_init(&atoms);
	for (int i = 0; i < ARRAY_SIZE(tests); i++) {
		apk_blob_t url = APK_BLOB_STR(tests[i].url);
		apk_blob_t res = apk_url_sanitize(APK_BLOB_STR(tests[i].url), &atoms);
		if (tests[i].sanitized) assert_blob_equal(APK_BLOB_STR(tests[i].sanitized), res);
		else assert_blob_identical(url, res);
	}
	apk_atom_free(&atoms);
}

APK_TEST(url_local) {
	assert_non_null(apk_url_local_file("/path/to/file", PATH_MAX));
	assert_non_null(apk_url_local_file("file:/path/to/file", PATH_MAX));
	assert_non_null(apk_url_local_file("file://localfile/path/to/file", PATH_MAX));
	assert_non_null(apk_url_local_file("test:/path/to/file", PATH_MAX));
	assert_non_null(apk_url_local_file("test_file://past-eos", 8));
	assert_null(apk_url_local_file("http://example.com", PATH_MAX));
	assert_null(apk_url_local_file("https://example.com", PATH_MAX));
	assert_null(apk_url_local_file("unknown://example.com", PATH_MAX));
}
