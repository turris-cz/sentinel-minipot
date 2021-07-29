#include <check.h>
#include <signal.h>

#include "../../src/utils.h"

#define SKIP 1
#define NO_SKIP 2

struct test_data {
	const uint8_t *str;
	size_t len;
	const uint8_t *to_skip;
	size_t to_skip_len;
	const uint8_t *res;
};

static const uint8_t to_skip[] = {SKIP};
static const uint8_t str_param[] = {3, 4};


START_TEST(str_len_0_test) {
	ck_assert_ptr_eq(skip_sel_bytes(str_param, 0, to_skip, sizeof(to_skip)),
		str_param);
} END_TEST


START_TEST(to_skip_len_0_test) {
	ck_assert_ptr_eq(skip_sel_bytes(str_param, sizeof(str_param), to_skip, 0),
		str_param);
} END_TEST

static const uint8_t str01_skip[] = {SKIP};
static const uint8_t str02_skip[] = {NO_SKIP};

static const uint8_t str03_skip[] = {SKIP, SKIP};
static const uint8_t str04_skip[] = {SKIP, NO_SKIP};

static const uint8_t str05_skip[] = {NO_SKIP, NO_SKIP};
static const uint8_t str06_skip[] = {NO_SKIP, SKIP};

static const uint8_t str07_skip[] = {SKIP, SKIP, SKIP};
static const uint8_t str08_skip[] = {SKIP, SKIP, NO_SKIP};
static const uint8_t str09_skip[] = {SKIP, NO_SKIP, SKIP};
static const uint8_t str10_skip[] = {SKIP, NO_SKIP, NO_SKIP};

static const uint8_t str11_skip[] = {NO_SKIP, NO_SKIP, SKIP};
static const uint8_t str12_skip[] = {NO_SKIP, NO_SKIP, NO_SKIP};
static const uint8_t str13_skip[] = {NO_SKIP, SKIP, SKIP};
static const uint8_t str14_skip[] = {NO_SKIP, SKIP, NO_SKIP};

static const struct test_data const skip_test_d[] = {
	{str01_skip, sizeof(str01_skip), to_skip, sizeof(to_skip), str01_skip + 1},
	{str02_skip, sizeof(str02_skip), to_skip, sizeof(to_skip), str02_skip},
	{str03_skip, sizeof(str03_skip), to_skip, sizeof(to_skip), str03_skip + 2},
	{str04_skip, sizeof(str04_skip), to_skip, sizeof(to_skip), str04_skip + 1},
	{str05_skip, sizeof(str05_skip), to_skip, sizeof(to_skip), str05_skip},
	{str06_skip, sizeof(str06_skip), to_skip, sizeof(to_skip), str06_skip},
	{str07_skip, sizeof(str07_skip), to_skip, sizeof(to_skip), str07_skip + 3},
	{str08_skip, sizeof(str08_skip), to_skip, sizeof(to_skip), str08_skip + 2},
	{str09_skip, sizeof(str09_skip), to_skip, sizeof(to_skip), str09_skip + 1},
	{str10_skip, sizeof(str10_skip), to_skip, sizeof(to_skip), str10_skip + 1},
	{str11_skip, sizeof(str11_skip), to_skip, sizeof(to_skip), str11_skip},
	{str12_skip, sizeof(str12_skip), to_skip, sizeof(to_skip), str12_skip},
	{str13_skip, sizeof(str13_skip), to_skip, sizeof(to_skip), str13_skip},
	{str14_skip, sizeof(str14_skip), to_skip, sizeof(to_skip), str14_skip},
};

START_TEST(skip_test) {
	ck_assert_ptr_eq(skip_sel_bytes(skip_test_d[_i].str, skip_test_d[_i].len,
		skip_test_d[_i].to_skip, skip_test_d[_i].to_skip_len),
		skip_test_d[_i].res);

} END_TEST


START_TEST(more_to_skip_test) {
	const uint8_t more_to_skip[] = {1, 2, 3, 4};
	const uint8_t str_more_to_skip[] = {1, 2, 3, 4};
	ck_assert_ptr_eq(skip_sel_bytes(str_more_to_skip, sizeof(str_more_to_skip),
		more_to_skip, sizeof(more_to_skip)), str_more_to_skip + 4);

} END_TEST

void suite_skip_sel_bytes(SRunner *runner) {

	Suite *suite = suite_create("skip_sel_bytes");

	TCase *param_tc = tcase_create("parameter check");
	tcase_add_test(param_tc, str_len_0_test);
	tcase_add_test(param_tc, to_skip_len_0_test);
	suite_add_tcase(suite, param_tc);

	TCase *skip_tc = tcase_create("skip");
	tcase_add_loop_test(skip_tc, skip_test, 0,
		sizeof(skip_test_d) / sizeof(*skip_test_d));
	suite_add_tcase(suite, skip_tc);

	TCase *more_to_skip_tc = tcase_create("more to skip");
	tcase_add_test(more_to_skip_tc, more_to_skip_test);
	suite_add_tcase(suite, more_to_skip_tc);

	srunner_add_suite(runner, suite);
}
