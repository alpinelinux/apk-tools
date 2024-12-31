#include "apk_test.h"
#include "apk_database.h"

static void _assert_repoline(apk_blob_t line, apk_blob_t tag, unsigned int type, apk_blob_t url, const char *const file, int lineno)
{
	struct apk_repoline rl;

	_assert_true(apk_repo_parse_line(line, &rl), "", file, lineno);
	_assert_blob_equal(tag, rl.tag, file, lineno);
	_assert_int_equal(type, rl.type, file, lineno);
	_assert_blob_equal(url, rl.url, file, lineno);
}
#define assert_repoline(line, tag, type, url) _assert_repoline(line, tag, type, url, __FILE__, __LINE__)

APK_TEST(db_repo_parse) {
	struct apk_repoline rl;
	apk_blob_t tag = APK_BLOB_STRLIT("@tag");
	apk_blob_t url = APK_BLOB_STRLIT("http://example.com");
	apk_blob_t index = APK_BLOB_STRLIT("http://example.com/index.adb");

	assert_repoline(url, APK_BLOB_NULL, APK_REPOTYPE_V2, url);
	assert_repoline(APK_BLOB_STRLIT("@tag http://example.com"), tag, APK_REPOTYPE_V2, url);
	assert_repoline(APK_BLOB_STRLIT("http://example.com/index.adb"), APK_BLOB_NULL, APK_REPOTYPE_NDX, index);

	assert_false(apk_repo_parse_line(APK_BLOB_STRLIT("http://example.com extra"), &rl));
	assert_false(apk_repo_parse_line(APK_BLOB_STRLIT("@tag v3 http://example.com extra"), &rl));
}
