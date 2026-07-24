#include "apk_test.h"
#include "apk_fs.h"

APK_TEST(fs_malicious_filename) {
	assert_false(apk_fs_is_malicious_filename(APK_BLOB_STRLIT("...")));
	assert_false(apk_fs_is_malicious_filename(APK_BLOB_STRLIT("..bar")));
	assert_false(apk_fs_is_malicious_filename(APK_BLOB_STRLIT(".bar")));
	assert_false(apk_fs_is_malicious_filename(APK_BLOB_STRLIT("bar")));
	assert_false(apk_fs_is_malicious_filename(APK_BLOB_STRLIT("båäö")));
	assert_true(apk_fs_is_malicious_filename(APK_BLOB_STRLIT("")));
	assert_true(apk_fs_is_malicious_filename(APK_BLOB_STRLIT(".")));
	assert_true(apk_fs_is_malicious_filename(APK_BLOB_STRLIT("..")));
	assert_true(apk_fs_is_malicious_filename(APK_BLOB_STRLIT("foobar/")));
	assert_true(apk_fs_is_malicious_filename(APK_BLOB_STRLIT("foo/bar")));
	assert_true(apk_fs_is_malicious_filename(APK_BLOB_STRLIT("foo""\x00""bar")));
	assert_true(apk_fs_is_malicious_filename(APK_BLOB_STRLIT("foo""\x10""bar")));
}

APK_TEST(fs_malicious_pathname) {
	assert_false(apk_fs_is_malicious_pathname(APK_BLOB_STRLIT("foo/foo")));
	assert_false(apk_fs_is_malicious_pathname(APK_BLOB_STRLIT("foo/..foo/foo")));
	assert_false(apk_fs_is_malicious_pathname(APK_BLOB_STRLIT("foo/foo/")));
	assert_false(apk_fs_is_malicious_pathname(APK_BLOB_STRLIT(".foo/foo")));
	assert_true(apk_fs_is_malicious_pathname(APK_BLOB_STRLIT("../foo")));
	assert_true(apk_fs_is_malicious_pathname(APK_BLOB_STRLIT("foo//foo")));
	assert_true(apk_fs_is_malicious_pathname(APK_BLOB_STRLIT("foo/../foo")));
	assert_true(apk_fs_is_malicious_pathname(APK_BLOB_STRLIT("foo/./foo")));
	assert_true(apk_fs_is_malicious_pathname(APK_BLOB_STRLIT("foo/\x1f/foo")));
}
