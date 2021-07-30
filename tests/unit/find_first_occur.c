#include <check.h>
#include <signal.h>
#include "../../src/utils.h"

#define FIND 1
#define NO_FIND 2

struct test_data {
	const uint8_t const *str;
	size_t len;
	const uint8_t const *find;
	size_t find_len;
	const uint8_t const *res;
};

static const uint8_t const find[] = {FIND};
static const uint8_t const str_param[] = {FIND, FIND};

START_TEST(str_len_0_test) {
	ck_assert_ptr_eq(find_first_occur(str_param, 0, find, sizeof(find)), str_param);
} END_TEST

START_TEST(find_len_0_test) {
	ck_assert_ptr_eq(find_first_occur(str_param, sizeof(str_param), find, 0),
		str_param + sizeof(str_param));
}

static const uint8_t const str01_find[] = {FIND};
static const uint8_t const str02_find[] = {NO_FIND};

static const uint8_t const str03_find[] = {FIND, FIND};
static const uint8_t const str04_find[] = {FIND, NO_FIND};
static const uint8_t const str05_find[] = {NO_FIND, FIND};
static const uint8_t const str06_find[] = {NO_FIND, NO_FIND};

static const uint8_t const str07_find[] = {FIND, FIND, FIND};
static const uint8_t const str08_find[] = {FIND, FIND, NO_FIND};

static const uint8_t const str09_find[] = {FIND, NO_FIND, FIND};
static const uint8_t const str10_find[] = {FIND, NO_FIND, NO_FIND};

static const uint8_t const str11_find[] = {NO_FIND, FIND, NO_FIND};
static const uint8_t const str12_find[] = {NO_FIND, FIND, FIND};

static const uint8_t const str13_find[] = {NO_FIND, NO_FIND, FIND};
static const uint8_t const str14_find[] = {NO_FIND, NO_FIND, NO_FIND};

static const struct test_data const find_d[] = {
	{str01_find, sizeof(str01_find), find, sizeof(find), str01_find},
	{str02_find, sizeof(str02_find), find, sizeof(find), str02_find + 1},
	{str03_find, sizeof(str03_find), find, sizeof(find), str03_find},
	{str04_find, sizeof(str04_find), find, sizeof(find), str04_find},
	{str05_find, sizeof(str05_find), find, sizeof(find), str05_find + 1},
	{str06_find, sizeof(str06_find), find, sizeof(find), str06_find + 2},
	{str07_find, sizeof(str07_find), find, sizeof(find), str07_find},
	{str08_find, sizeof(str08_find), find, sizeof(find), str08_find},
	{str09_find, sizeof(str09_find), find, sizeof(find), str09_find},
	{str10_find, sizeof(str10_find), find, sizeof(find), str10_find},
	{str11_find, sizeof(str11_find), find, sizeof(find), str11_find + 1},
	{str12_find, sizeof(str12_find), find, sizeof(find), str12_find + 1},
	{str13_find, sizeof(str13_find), find, sizeof(find), str13_find + 2},
	{str14_find, sizeof(str14_find), find, sizeof(find), str14_find + 3},
};

START_TEST (find_test) {
	ck_assert_ptr_eq(find_first_occur(find_d[_i].str, find_d[_i].len,
		find_d[_i].find, find_d[_i].find_len), find_d[_i].res);
} END_TEST

static const uint8_t const find_more[] = {1, 2, 3, 4};

static const uint8_t const str01_find_more[] = {2};
static const uint8_t const str02_find_more[] = {3};
static const uint8_t const str03_find_more[] = {4};

static const struct test_data const find_more_d[] = {
	{str01_find_more, sizeof(str01_find_more), find_more, sizeof(find_more),
		str01_find_more},
	{str02_find_more, sizeof(str02_find_more), find_more, sizeof(find_more),
		str02_find_more},
	{str03_find_more, sizeof(str03_find_more), find_more, sizeof(find_more),
		str03_find_more},
};

START_TEST (find_more_test) {
	ck_assert_ptr_eq(find_first_occur(find_more_d[_i].str, find_more_d[_i].len,
		find_more_d[_i].find, find_more_d[_i].find_len), find_more_d[_i].res);
} END_TEST

void suite_find_first_occur(SRunner *runner) {

	Suite *suite = suite_create("find_first_occur");

	TCase *param_tc = tcase_create("param test");
	tcase_add_test(param_tc, str_len_0_test);
	tcase_add_test(param_tc, find_len_0_test);
	suite_add_tcase(suite, param_tc);

	TCase *find_tc = tcase_create("find");
	tcase_add_loop_test(find_tc, find_test, 0,
		sizeof(find_d) / sizeof(*find_d));
	suite_add_tcase(suite, find_tc);

	TCase *find_more_tc = tcase_create("find more");
	tcase_add_loop_test(find_more_tc, find_more_test, 0,
		sizeof(find_more_d) / sizeof(*find_more_d));
	suite_add_tcase(suite, find_more_tc);

	srunner_add_suite(runner, suite);
}
