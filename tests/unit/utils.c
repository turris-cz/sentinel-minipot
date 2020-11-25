#include <check.h>
#include <stdbool.h>
#include "utils.h"

START_TEST(example) {
	ck_assert(true);
}
END_TEST


void suite_utils(SRunner *runner) {
	Suite *suite = suite_create("utils");

	TCase *t_check_serv_data = tcase_create("check_serv_data");
	tcase_add_test(t_check_serv_data, example);
	suite_add_tcase(suite, t_check_serv_data);

	srunner_add_suite(runner, suite);
}
