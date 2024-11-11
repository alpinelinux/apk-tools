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
