#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#define assert_ptr_ok(c) _assert_true(!IS_ERR(c), #c, __FILE__, __LINE__)

void test_register(const char *, UnitTestFunction);

#define APK_TEST(test_name) \
	static void test_name(void **); \
	__attribute__((constructor)) static void _test_register_##x(void) { test_register(#test_name, test_name); } \
	static void test_name(void **)
