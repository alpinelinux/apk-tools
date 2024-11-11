#include "apk_test.h"

static int num_tests;
static struct CMUnitTest all_tests[1000];

void test_register(const char *name, UnitTestFunction f)
{
	all_tests[num_tests++] = (struct CMUnitTest) {
		.name = name,
		.test_func = f,
	};
}

int main(void)
{
	return _cmocka_run_group_tests("unit_tests", all_tests, num_tests, NULL, NULL);
}
