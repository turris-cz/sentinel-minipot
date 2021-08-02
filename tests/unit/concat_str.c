#include <check.h>
#include "../../src/utils.h"

#define STR1 "sasasasasasasasa"
#define STR2 "aasdssfdg"
#define STR3 "qwqw"

static char *res;

static void teardown() {
	free(res);
}

START_TEST(concat_test1) {
	char *str = "";
	concat_str(&res, 0);
	ck_assert_str_eq(res, str);
} END_TEST

START_TEST(concat_test2) {
	char *str = STR1;
	concat_str(&res, 1, STR1);
	ck_assert_str_eq(res, str);
} END_TEST

START_TEST(concat_test3) {
	char *str = STR1 STR2;
	concat_str(&res, 2, STR1, STR2);
	ck_assert_str_eq(res, str);
} END_TEST

START_TEST(concat_test4) {
	char *str = STR1 STR2 STR3;
	concat_str(&res, 3, STR1, STR2, STR3);
	ck_assert_str_eq(res, str);
} END_TEST

START_TEST(concat_test5) {
	char *str = STR1;
	concat_str(&res, 1, STR1, STR2, STR3);
	ck_assert_str_eq(res, str);
} END_TEST

void suite_concat_str(SRunner *runner) {

	Suite *suite = suite_create("concat_str");

	TCase *concat_tc = tcase_create("concatenate");
	tcase_add_checked_fixture(concat_tc, NULL, teardown);
	tcase_add_test(concat_tc, concat_test1);
	tcase_add_test(concat_tc, concat_test2);
	tcase_add_test(concat_tc, concat_test3);
	tcase_add_test(concat_tc, concat_test4);
	tcase_add_test(concat_tc, concat_test5);
	suite_add_tcase(suite, concat_tc);

	srunner_add_suite(runner, suite);
}

