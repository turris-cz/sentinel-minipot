#include <check.h>
#include "../../src/utils.h"

const uint8_t first_b_errors[][1] = {0, 128, 193, 245, 255};

const uint8_t second_b_errors[][2] = {
	{194, 0},
	{194, 127},
	{194, 192},
	{194, 255},
	{223, 0},
	{223, 127},
	{223, 192},
	{223, 255},
	{224, 0},
	{224, 159},
	{224, 192},
	{224, 255},
	{225, 0},
	{225, 127},
	{225, 192},
	{225, 255},
	{236, 0},
	{236, 127},
	{236, 192},
	{236, 255},
	{238, 0},
	{238, 127},
	{238, 192},
	{238, 255},
	{239, 0},
	{239, 127},
	{239, 192},
	{239, 255},
	{237, 0},
	{237, 127},
	{237, 160},
	{237, 255},
	{240, 0},
	{240, 143},
	{240, 192},
	{240, 255},
	{241, 0},
	{241, 127},
	{241, 192},
	{241, 255},
	{243, 0},
	{243, 127},
	{243, 192},
	{243, 255},
	{244, 0},
	{244, 127},
	{244, 144},
	{244, 255},
};
const uint8_t third_b_errors[][3] = {
	{224, 160, 0},
	{224, 160, 127},
	{224, 160, 192},
	{224, 160, 255},
	{224, 191, 0},
	{224, 191, 127},
	{224, 191, 192},
	{224, 191, 255},
	{225, 128, 0},
	{225, 128, 127},
	{225, 128, 192},
	{225, 128, 255},
	{225, 191, 0},
	{225, 191, 127},
	{225, 191, 192},
	{225, 191, 255},
	{236, 128, 0},
	{236, 128, 127},
	{236, 128, 192},
	{236, 128, 255},
	{236, 191, 0},
	{236, 191, 127},
	{236, 191, 192},
	{236, 191, 255},
	{238, 128, 0},
	{238, 128, 127},
	{238, 128, 192},
	{238, 128, 255},
	{238, 191, 0},
	{238, 191, 127},
	{238, 191, 192},
	{238, 191, 255},
	{239, 128, 0},
	{239, 128, 127},
	{239, 128, 192},
	{239, 128, 255},
	{239, 191, 0},
	{239, 191, 127},
	{239, 191, 192},
	{239, 191, 255},
	{237, 128, 0},
	{237, 128, 127},
	{237, 128, 192},
	{237, 128, 255},
	{237, 159, 0},
	{237, 159, 127},
	{237, 159, 192},
	{237, 159, 255},
	{240, 144, 0},
	{240, 144, 127},
	{240, 144, 192},
	{240, 144, 255},
	{240, 191, 0},
	{240, 191, 127},
	{240, 191, 192},
	{240, 191, 255},
	{241, 128, 0},
	{241, 128, 127},
	{241, 128, 192},
	{241, 128, 255},
	{241, 191, 0},
	{241, 191, 127},
	{241, 191, 192},
	{241, 191, 255},
	{243, 128, 0},
	{243, 128, 127},
	{243, 128, 192},
	{243, 128, 255},
	{243, 191, 0},
	{243, 191, 127},
	{243, 191, 192},
	{243, 191, 255},
	{244, 128, 0},
	{244, 143, 127},
	{244, 143, 192},
	{244, 143, 255},
};

const uint8_t fourth_b_errors[][4] = {
	{240, 144, 128, 0},
	{240, 144, 128, 127},
	{240, 144, 128, 192},
	{240, 144, 128, 255},
	{240, 144, 191, 0},
	{240, 144, 191, 127},
	{240, 144, 191, 192},
	{240, 144, 191, 255},
	{240, 191, 128, 0},
	{240, 191, 128, 127},
	{240, 191, 128, 192},
	{240, 191, 128, 255},
	{240, 191, 191, 0},
	{240, 191, 191, 127},
	{240, 191, 191, 192},
	{240, 191, 191, 255},
	{241, 128, 128, 0},
	{241, 128, 128, 127},
	{241, 128, 128, 192},
	{241, 128, 128, 255},
	{241, 128, 191, 0},
	{241, 128, 191, 127},
	{241, 128, 191, 192},
	{241, 128, 191, 255},
	{241, 191, 128, 0},
	{241, 191, 128, 127},
	{241, 191, 128, 192},
	{241, 191, 128, 255},
	{241, 191, 191, 0},
	{241, 191, 191, 127},
	{241, 191, 191, 192},
	{241, 191, 191, 255},
	{243, 128, 128, 0},
	{243, 128, 128, 127},
	{243, 128, 128, 192},
	{243, 128, 128, 255},
	{243, 128, 191, 0},
	{243, 128, 191, 127},
	{243, 128, 191, 192},
	{243, 128, 191, 255},
	{243, 191, 128, 0},
	{243, 191, 128, 127},
	{243, 191, 128, 192},
	{243, 191, 128, 255},
	{243, 191, 191, 0},
	{243, 191, 191, 127},
	{243, 191, 191, 192},
	{243, 191, 191, 255},
	{244, 128, 128, 0},
	{244, 128, 128, 127},
	{244, 128, 128, 192},
	{244, 128, 128, 255},
	{244, 128, 191, 0},
	{244, 128, 191, 127},
	{244, 128, 191, 192},
	{244, 128, 191, 255},
	{244, 143, 128, 0},
	{244, 143, 128, 127},
	{244, 143, 128, 192},
	{244, 143, 128, 255},
	{244, 143, 191, 0},
	{244, 143, 191, 127},
	{244, 143, 191, 192},
	{244, 143, 191, 255},
};

const uint8_t fourth_b_missing[][3] = {
	{240, 144, 128},
	{240, 144, 191},
	{240, 191, 128},
	{240, 191, 191},
	{241, 128, 128},
	{241, 128, 191},
	{241, 191, 128},
	{241, 191, 191},
	{243, 128, 128},
	{243, 128, 191},
	{243, 191, 128},
	{243, 191, 191},
	{244, 128, 128},
	{244, 128, 191},
	{244, 143, 128},
	{244, 143, 191},
};

const uint8_t third_b_missing[][2] = {
	{224, 160},
	{224, 191},
	{225, 128},
	{225, 191},
	{236, 128},
	{236, 191},
	{238, 128},
	{238, 191},
	{239, 128},
	{239, 191},
	{237, 128},
	{237, 159},
	{240, 144},
	{240, 191},
	{241, 128},
	{241, 191},
	{243, 128},
	{243, 191},
	{244, 128},
};

const uint8_t second_b_missing[][1] = {194, 223, 224, 225, 236, 238, 239, 237,
	240, 241, 243, 244};

const uint8_t one_b_chars[][1] = {1, 127};

const uint8_t two_b_chars[][2] = {
	{194, 128},
	{194, 191},
	{223, 128},
	{223, 191},
};

const uint8_t three_b_chars[][3] = {
	{224, 160, 128},
	{224, 160, 191},
	{224, 191, 128},
	{224, 191, 191},
	{225, 128, 128},
	{225, 128, 191},
	{225, 191, 128},
	{225, 191, 191},
	{236, 128, 128},
	{236, 128, 191},
	{236, 191, 128},
	{236, 191, 191},
	{238, 128, 128},
	{238, 128, 191},
	{238, 191, 128},
	{238, 191, 191},
	{239, 128, 128},
	{239, 128, 191},
	{239, 191, 128},
	{239, 191, 191},
	{237, 128, 128},
	{237, 128, 191},
	{237, 159, 128},
	{237, 159, 191},
};

uint8_t four_b_chars[][4] = {
	{240, 144, 128, 128},
	{240, 144, 128, 191},
	{240, 144, 191, 128},
	{240, 144, 191, 191},
	{240, 191, 128, 128},
	{240, 191, 128, 191},
	{240, 191, 191, 128},
	{240, 191, 191, 191},
	{241, 128, 128, 128},
	{241, 128, 128, 191},
	{241, 128, 191, 128},
	{241, 128, 191, 191},
	{241, 191, 128, 128},
	{241, 191, 128, 191},
	{241, 191, 191, 128},
	{241, 191, 191, 191},
	{243, 128, 128, 128},
	{243, 128, 128, 191},
	{243, 128, 191, 128},
	{243, 128, 191, 191},
	{243, 191, 128, 128},
	{243, 191, 128, 191},
	{243, 191, 191, 128},
	{243, 191, 191, 191},
	{244, 128, 128, 128},
	{244, 128, 128, 191},
	{244, 128, 191, 128},
	{244, 128, 191, 191},
	{244, 143, 128, 128},
	{244, 143, 128, 191},
	{244, 143, 191, 128},
	{244, 143, 191, 191},
};

START_TEST(test_first_b_errors) {
	ck_assert(check_serv_data(first_b_errors[_i], 1));
}
END_TEST

START_TEST(test_second_b_errors) {
	ck_assert(check_serv_data(second_b_errors[_i], 2));
}
END_TEST

START_TEST(test_third_b_errors) {
	ck_assert(check_serv_data(third_b_errors[_i], 3));
}
END_TEST

START_TEST(test_fourth_b_errors) {
	ck_assert(check_serv_data(fourth_b_errors[_i], 4));
}
END_TEST

START_TEST(test_fourth_b_missing) {
	ck_assert(check_serv_data(fourth_b_missing[_i], 3));
}
END_TEST

START_TEST(test_third_b_missing) {
	ck_assert(check_serv_data(third_b_missing[_i], 2));
}
END_TEST

START_TEST(test_second_b_missing) {
	ck_assert(check_serv_data(second_b_missing[_i], 1));
}
END_TEST

START_TEST(test_first_b_missing) {
	ck_assert(!check_serv_data(NULL, 0));
}
END_TEST

START_TEST(test_one_byte_char) {
	ck_assert(!check_serv_data(one_b_chars[_i], 1));
}
END_TEST

START_TEST(test_two_byte_char) {
	ck_assert(!check_serv_data(two_b_chars[_i], 2));
}
END_TEST

START_TEST(test_three_byte_char) {
	ck_assert(!check_serv_data(three_b_chars[_i], 3));
}
END_TEST

START_TEST(test_four_byte_char) {
	ck_assert(!check_serv_data(four_b_chars[_i], 4));
}
END_TEST

void suite_check_serv_data(SRunner *runner) {

	Suite *suite = suite_create("check_serv_data");

	TCase *tcase_first_b_errors = tcase_create("first_byte_errors");
	tcase_add_loop_test(tcase_first_b_errors, test_first_b_errors, 0,
		sizeof(first_b_errors) / sizeof(*first_b_errors));
	suite_add_tcase(suite, tcase_first_b_errors);

	TCase *tcase_second_b_errors = tcase_create("second_byte_errors");
	tcase_add_loop_test(tcase_second_b_errors, test_second_b_errors, 0,
		sizeof(second_b_errors) / sizeof(*second_b_errors));
	suite_add_tcase(suite, tcase_second_b_errors);

	TCase *tcase_third_b_errors = tcase_create("third_byte_errors");
	tcase_add_loop_test(tcase_third_b_errors, test_third_b_errors, 0,
		sizeof(third_b_errors) / sizeof(*third_b_errors));
	suite_add_tcase(suite, tcase_third_b_errors);

	TCase *tcase_fourth_b_errors = tcase_create("fourth_byte_errors");
	tcase_add_loop_test(tcase_fourth_b_errors, test_fourth_b_errors, 0,
		sizeof(fourth_b_errors) / sizeof(*fourth_b_errors));
	suite_add_tcase(suite, tcase_fourth_b_errors);

	TCase *tcase_fourth_b_missing = tcase_create("fourth_byte_missing");
	tcase_add_loop_test(tcase_fourth_b_missing, test_fourth_b_missing, 0,
		sizeof(fourth_b_missing) / sizeof(*fourth_b_missing));
	suite_add_tcase(suite, tcase_fourth_b_missing);

	TCase *tcase_third_b_missing = tcase_create("third_byte_missing");
	tcase_add_loop_test(tcase_third_b_missing, test_third_b_missing, 0,
		sizeof(third_b_missing) / sizeof(*third_b_missing));
	suite_add_tcase(suite, tcase_third_b_missing);

	TCase *tcase_second_b_missing = tcase_create("second_byte_missing");
	tcase_add_loop_test(tcase_second_b_missing, test_second_b_missing, 0,
		sizeof(second_b_missing) / sizeof(*second_b_missing));
	suite_add_tcase(suite, tcase_second_b_missing);

	TCase *tcase_first_b_missing = tcase_create("first_byte_missing");
	tcase_add_test(tcase_first_b_missing, test_first_b_missing);
	suite_add_tcase(suite, tcase_first_b_missing);

	TCase *tcase_one_byte_char = tcase_create("one_byte_char");
	tcase_add_loop_test(tcase_one_byte_char, test_one_byte_char, 0,
		sizeof(one_b_chars) / sizeof(*one_b_chars));
	suite_add_tcase(suite, tcase_one_byte_char);

	TCase *tcase_two_byte_char = tcase_create("two_byte_char");
	tcase_add_loop_test(tcase_two_byte_char, test_two_byte_char, 0,
		sizeof(two_b_chars) / sizeof(*two_b_chars));
	suite_add_tcase(suite, tcase_two_byte_char);

	TCase *tcase_three_byte_char = tcase_create("three_byte_char");
	tcase_add_loop_test(tcase_three_byte_char, test_three_byte_char, 0,
		sizeof(three_b_chars) / sizeof(*three_b_chars));
	suite_add_tcase(suite, tcase_three_byte_char);

	TCase *tcase_four_byte_char = tcase_create("four_byte_char");
	tcase_add_loop_test(tcase_four_byte_char, test_four_byte_char, 0,
		sizeof(four_b_chars) / sizeof(*four_b_chars));
	suite_add_tcase(suite, tcase_four_byte_char);

	srunner_add_suite(runner, suite);
}
