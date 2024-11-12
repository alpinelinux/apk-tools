#include "apk_test.h"
#include "apk_blob.h"

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
