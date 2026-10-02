#include <stdio.h>
#include <string.h>

#include "apk_test.h"
#include "apk_tar.h"

#define TAR_BLOCK_SIZE 512

static void make_tar_header(char *hdr, const char *name, char typeflag, size_t size)
{
	memset(hdr, 0, TAR_BLOCK_SIZE);
	memcpy(hdr, name, strlen(name));
	snprintf(hdr + 124, 12, "%011o", (unsigned int)size);
	hdr[156] = typeflag;
	memcpy(hdr + 257, "ustar", 5);
}

static int tar_test_entry_parser(void *ctx, const struct apk_file_info *ae,
				struct apk_istream *is)
{
	int *calls = ctx;
	(void)is;
	(*calls)++;
	assert_string_equal(ae->name, "evil");
	return 0;
}

APK_TEST(tar_rejects_truncated_pax_length) {
	static const char pax[] = "4294967316 path=XXX\n\n12 path=evil\n";
	char archive[3 * TAR_BLOCK_SIZE] = {};
	struct apk_istream is;
	struct apk_id_cache idc = { .root_fd = AT_FDCWD };
	int calls = 0, r;

	make_tar_header(archive, "PaxHeader", 'x', sizeof(pax) - 1);
	memcpy(archive + TAR_BLOCK_SIZE, pax, sizeof(pax) - 1);
	make_tar_header(archive + 2 * TAR_BLOCK_SIZE, "file", '0', 0);

	apk_istream_from_blob(&is, APK_BLOB_PTR_LEN(archive, sizeof archive));
	r = apk_tar_parse(&is, tar_test_entry_parser, &calls, &idc);
	assert_true(r < 0);
	assert_int_equal(calls, 0);
}
