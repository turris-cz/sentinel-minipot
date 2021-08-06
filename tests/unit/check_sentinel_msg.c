#include <check.h>
#include "../../src/minipot_pipe.h"

#define STR "ahddds"

static struct uint8_t_pair invalid_data01 = {
	.key = NULL, .key_len = strlen(STR), .val = STR, .val_len = strlen(STR)
};

static struct uint8_t_pair invalid_data02 = {
	.key = STR, .key_len = 0, .val = STR, .val_len = strlen(STR)
};

static struct uint8_t_pair invalid_data03 = {
	.key = STR, .key_len = strlen(STR), .val = NULL, .val_len = strlen(STR)
};

static const struct sentinel_msg invalid_messgess[] = {
	{0, "a", "b", "c", NULL, 0},
	{1, NULL, "b", "c", NULL, 0},
	{1, "", "b", "c", NULL, 0},
	{1, "a", NULL, "c", NULL, 0},
	{1, "a", "", "c", NULL, 0},
	{1, "a", "b", NULL, NULL, 0},
	{1, "a", "b", "", NULL, 0},
	{1, "a", "b", "c", NULL, 1},
	{1, "a", "b", "c", &invalid_data01, 1},
	{1, "a", "b", "c", &invalid_data02, 1},
	{1, "a", "b", "c", &invalid_data03, 1},
};

START_TEST (fail_test) {
	ck_assert_int_eq(check_sentinel_msg(&invalid_messgess[_i]), -1);
} END_TEST

static struct uint8_t_pair valid_data01 = {
	.key = STR, .key_len = strlen(STR), .val = STR, .val_len = strlen(STR)
};

static struct uint8_t_pair valid_data02 = {
	.key = STR, .key_len = strlen(STR), .val = NULL, .val_len = 0
};


static struct uint8_t_pair valid_data03 = {
	.key = STR, .key_len = strlen(STR), .val = STR, .val_len = 0
};


static const struct sentinel_msg valid_messgess[] = {
	{1, "a", "b", "c", NULL, 0},
	{1, "a", "b", "c", &valid_data01, 1},
	{1, "a", "b", "c", &valid_data02, 1},
};

START_TEST (pass_test) {
	ck_assert_int_eq(check_sentinel_msg(&valid_messgess[_i]), 0);
} END_TEST


void suite_check_sentinel_msg(SRunner *runner) {

	Suite *suite = suite_create("check_sentinel_msg");

	TCase *fail_tc = tcase_create("fail");
	tcase_add_loop_test(fail_tc, fail_test, 0,
		sizeof(invalid_messgess) / sizeof(*invalid_messgess));
	suite_add_tcase(suite, fail_tc);


	TCase *pass_tc = tcase_create("pass");
	tcase_add_loop_test(pass_tc, pass_test, 0,
		sizeof(valid_messgess) / sizeof(*valid_messgess));
	suite_add_tcase(suite, pass_tc);

	srunner_add_suite(runner, suite);
}

