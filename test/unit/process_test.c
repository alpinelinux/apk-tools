#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "apk_test.h"
#include "apk_print.h"
#include "apk_process.h"
#include "apk_io.h"

#define writestr(fd, str) write(fd, str, sizeof(str)-1)

struct cached_out {
	struct apk_out out;
	char buf_err[256], buf_out[256];
};

static void open_out(struct cached_out *co)
{
	co->out = (struct apk_out) {
		.out = fmemopen(co->buf_out, sizeof co->buf_out, "w"),
		.err = fmemopen(co->buf_err, sizeof co->buf_err, "w"),
	};
	assert_non_null(co->out.out);
	assert_non_null(co->out.err);
}

static void assert_output_equal(struct cached_out *co, const char *expected_err, const char *expected_out)
{
	fputc(0, co->out.out);
	fclose(co->out.out);
	fputc(0, co->out.err);
	fclose(co->out.err);

	assert_string_equal(co->buf_err, expected_err);
	assert_string_equal(co->buf_out, expected_out);
}

APK_TEST(pid_logging) {
	struct cached_out co;
	struct apk_process p;

	open_out(&co);
	assert_int_equal(0, apk_process_init(&p, "test0", &co.out, NULL));
	if (apk_process_fork(&p) == 0) {
		writestr(STDERR_FILENO, "error1\nerror2\n");
		writestr(STDOUT_FILENO, "hello1\nhello2\n");
		close(STDOUT_FILENO);
		usleep(10000);
		writestr(STDERR_FILENO, "more\nlastline");
		exit(0);
	}

	assert_int_equal(0, apk_process_run(&p));
	assert_output_equal(&co,
		"test0: error1\n"
		"test0: error2\n"
		"test0: more\n"
		"test0: lastline\n",

		"test0: hello1\n"
		"test0: hello2\n");
}

APK_TEST(pid_error_exit) {
	struct cached_out co;
	struct apk_process p;

	open_out(&co);
	assert_int_equal(0, apk_process_init(&p, "test1", &co.out, NULL));
	if (apk_process_fork(&p) == 0) {
		exit(100);
	}

	assert_int_equal(-1, apk_process_run(&p));
	assert_output_equal(&co,
		"ERROR: test1: exited with error 100\n",
		"");
}

APK_TEST(pid_input_partial) {
	struct cached_out co;
	struct apk_process p;

	open_out(&co);
	assert_int_equal(0, apk_process_init(&p, "test2", &co.out, apk_istream_from_file(AT_FDCWD, "/dev/zero")));
	if (apk_process_fork(&p) == 0) {
		char buf[1024];
		int left = 128*1024;
		while (left) {
			int n = read(STDIN_FILENO, buf, min(left, sizeof buf));
			if (n <= 0) exit(100);
			left -= n;
		}
		writestr(STDOUT_FILENO, "success\n");
		exit(0);
	}

	assert_int_equal(-2, apk_process_run(&p));
	assert_output_equal(&co,
		"",
		"test2: success\n");
}

APK_TEST(pid_input_full) {
	struct cached_out co;
	struct apk_process p;

	open_out(&co);
	assert_int_equal(0, apk_process_init(&p, "test3", &co.out, apk_istream_from_file(AT_FDCWD, "version.data")));
	if (apk_process_fork(&p) == 0) {
		char buf[1024];
		writestr(STDOUT_FILENO, "start reading!\n");
		usleep(10000);
		while (1) {
			int n = read(STDIN_FILENO, buf, sizeof buf);
			if (n < 0) exit(100);
			if (n == 0) break;
		}
		writestr(STDOUT_FILENO, "success\n");
		exit(0);
	}

	assert_int_equal(0, apk_process_run(&p));
	assert_output_equal(&co,
		"",
		"test3: start reading!\n"
		"test3: success\n");
}

static void test_process_istream(int rc, char *arg, const char *expect_err, const char *expect_out)
{
	struct cached_out co;
	char out[256], *argv[] = { "../process-istream.sh", arg, NULL };

	open_out(&co);
	struct apk_istream *is = apk_process_istream(argv, &co.out, "process-istream");
	assert_ptr_ok(is);

	int n = apk_istream_read_max(is, out, sizeof out);
	assert_int_equal(rc, apk_istream_close(is));

	assert_output_equal(&co, expect_err, "");
	assert_int_equal(strlen(expect_out), n);
	assert_memory_equal(expect_out, out, n);
}

APK_TEST(pid_istream_ok) {
	test_process_istream(0, "ok",
		"process-istream: stderr text\n"
		"process-istream: stderr again\n",
		"hello\nhello again\n");
}

APK_TEST(pid_istream_fail) {
	test_process_istream(-APKE_REMOTE_IO, "fail",
		"process-istream: stderr text\n"
		"ERROR: process-istream: exited with error 10\n",
		"hello\n");
}
