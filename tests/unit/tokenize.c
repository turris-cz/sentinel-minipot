#include <check.h>
#include <signal.h>
#include "../../src/utils.h"

#define SEP 1
#define TOK 2

static const uint8_t str_param[] = {1, 2, 3, 4, 5, 6};
static struct token tokens_param[(sizeof(str_param) / 2) + 1];
static const uint8_t sep_param[] = {11, 12};

START_TEST(str_len_0_test) {
	tokenize(str_param, 0, tokens_param, sizeof(tokens_param),
		sep_param, sizeof(sep_param));
} END_TEST

START_TEST(tokens_len_0_test) {
	tokenize(str_param, sizeof(str_param), tokens_param, 0, sep_param,
		sizeof(sep_param));
} END_TEST

START_TEST(sep_len_0_test) {
	tokenize(str_param, sizeof(str_param), tokens_param, sizeof(tokens_param),
		sep_param, 0);
}

static const uint8_t const sep[] = {SEP};
// DO NOT FORGET TO MODIFY LENGTH 
static struct token tokens[10];

static void setup() {
	memset(tokens, 0, sizeof(tokens));
}

#define ck_assert_token(token, start, ln) do { \
	ck_assert_ptr_eq(token.start_ptr, start); \
	ck_assert_uint_eq(token.len, ln); \
} while(0) \

// sp
START_TEST (tokenize_test01) {
	const uint8_t const str[] = {SEP};
	ck_assert_uint_eq(tokenize(str, sizeof(str), tokens, sizeof(tokens),
		sep, sizeof(sep)), 0);
	for (size_t i = 0; i < sizeof(tokens) / sizeof(*tokens); i++)
		ck_assert_token(tokens[i], NULL, 0);
} END_TEST

// sp sp
START_TEST (tokenize_test02) {
	const uint8_t const str[] = {SEP, SEP};
	ck_assert_uint_eq(tokenize(str, sizeof(str), tokens, sizeof(tokens),
		sep, sizeof(sep)), 0);
	for (size_t i = 0; i < sizeof(tokens) / sizeof(*tokens); i++)
		ck_assert_token(tokens[i], NULL, 0);
} END_TEST

// sp tk
START_TEST (tokenize_test03) {
	const uint8_t const str[] = {SEP, TOK};
	ck_assert_uint_eq(tokenize(str, sizeof(str), tokens, sizeof(tokens),
		sep, sizeof(sep)), 1);
	ck_assert_token(tokens[0], str + 1, 1);
	for (size_t i = 1; i < sizeof(tokens)/ sizeof(*tokens); i++)
		ck_assert_token(tokens[i], NULL, 0);
} END_TEST

// sp sp sp
START_TEST (tokenize_test04) {
	const uint8_t const str[] = {SEP, SEP, SEP};
	ck_assert_uint_eq(tokenize(str, sizeof(str), tokens, sizeof(tokens),
		sep, sizeof(sep)), 0);
	for (size_t i = 0; i < sizeof(tokens)/ sizeof(*tokens); i++)
		ck_assert_token(tokens[i], NULL, 0);
} END_TEST

// sp sp tk
START_TEST (tokenize_test05) {
	const uint8_t const str[] = {SEP, SEP, TOK};
	ck_assert_uint_eq(tokenize(str, sizeof(str), tokens, sizeof(tokens),
		sep, sizeof(sep)), 1);
	ck_assert_token(tokens[0], str + 2, 1);
	for (size_t i = 1; i < sizeof(tokens)/ sizeof(*tokens); i++)
		ck_assert_token(tokens[i], NULL, 0);
} END_TEST


// sp tk sp
START_TEST (tokenize_test06) {
	const uint8_t const str[] = {SEP, TOK, SEP};
	ck_assert_uint_eq(tokenize(str, sizeof(str), tokens, sizeof(tokens),
		sep, sizeof(sep)), 1);
	ck_assert_token(tokens[0], str + 1, 1);
	for (size_t i = 1; i < sizeof(tokens)/ sizeof(*tokens); i++)
		ck_assert_token(tokens[i], NULL, 0);
} END_TEST


// sp tk tk
START_TEST (tokenize_test07) {
	const uint8_t const str[] = {SEP, TOK, TOK};
	ck_assert_uint_eq(tokenize(str, sizeof(str), tokens, sizeof(tokens),
		sep, sizeof(sep)), 1);
	ck_assert_token(tokens[0], str + 1, 2);
	for (size_t i = 1; i < sizeof(tokens)/ sizeof(*tokens); i++)
		ck_assert_token(tokens[i], NULL, 0);
} END_TEST


// tk
START_TEST (tokenize_test100) {
	const uint8_t const str[] = {TOK};
	ck_assert_uint_eq(tokenize(str, sizeof(str), tokens, sizeof(tokens),
		sep, sizeof(sep)), 1);
	ck_assert_token(tokens[0], str, 1);
	for (size_t i = 1; i < sizeof(tokens) / sizeof(*tokens); i++)
		ck_assert_token(tokens[i], NULL, 0);
} END_TEST


// tk sp
START_TEST (tokenize_test101) {
	const uint8_t const str[] = {TOK, SEP};
	ck_assert_uint_eq(tokenize(str, sizeof(str), tokens, sizeof(tokens),
		sep, sizeof(sep)), 1);
	ck_assert_token(tokens[0], str, 1);
	for (size_t i = 1; i < sizeof(tokens) / sizeof(*tokens); i++)
		ck_assert_token(tokens[i], NULL, 0);
} END_TEST


// tk tk
START_TEST (tokenize_test102) {
	const uint8_t const str[] = {TOK, TOK};
	ck_assert_uint_eq(tokenize(str, sizeof(str), tokens, sizeof(tokens),
		sep, sizeof(sep)), 1);
	ck_assert_token(tokens[0], str, 2);
	for (size_t i = 1; i < sizeof(tokens) / sizeof(*tokens); i++)
		ck_assert_token(tokens[i], NULL, 0);
} END_TEST


// tk sp sp
START_TEST (tokenize_test103) {
	const uint8_t const str[] = {TOK, SEP, SEP};
	ck_assert_uint_eq(tokenize(str, sizeof(str), tokens, sizeof(tokens),
		sep, sizeof(sep)), 1);
	ck_assert_token(tokens[0], str, 1);
	for (size_t i = 1; i < sizeof(tokens) / sizeof(*tokens); i++)
		ck_assert_token(tokens[i], NULL, 0);
} END_TEST


// tk sp tk
START_TEST (tokenize_test104) {
	const uint8_t const str[] = {TOK, SEP, TOK};
	ck_assert_uint_eq(tokenize(str, sizeof(str), tokens, sizeof(tokens),
		sep, sizeof(sep)), 2);
	ck_assert_token(tokens[0], str, 1);
	ck_assert_token(tokens[1], str + 2, 1);
	for (size_t i = 2; i < sizeof(tokens) / sizeof(*tokens); i++)
		ck_assert_token(tokens[i], NULL, 0);
} END_TEST


// tk tk sp
START_TEST (tokenize_test105) {
	const uint8_t const str[] = {TOK, TOK, SEP};
	ck_assert_uint_eq(tokenize(str, sizeof(str), tokens, sizeof(tokens),
		sep, sizeof(sep)), 1);
	ck_assert_token(tokens[0], str, 2);
	for (size_t i = 1; i < sizeof(tokens) / sizeof(*tokens); i++)
		ck_assert_token(tokens[i], NULL, 0);
} END_TEST

// tk tk tk 
START_TEST (tokenize_test106) {
	const uint8_t const str[] = {TOK, TOK, TOK};
	ck_assert_uint_eq(tokenize(str, sizeof(str), tokens, sizeof(tokens),
		sep, sizeof(sep)), 1);
	ck_assert_token(tokens[0], str, 3);
	for (size_t i = 1; i < sizeof(tokens) / sizeof(*tokens); i++)
		ck_assert_token(tokens[i], NULL, 0);
} END_TEST

START_TEST(tokenize_more_sep_test) {
	const uint8_t const sep[] = {1, 2, 3, 4};
	const uint8_t const str[] = {1, 2, 3, 5, 6, 7, 4, 3, 8, 9, 1, 2};
	ck_assert_uint_eq(tokenize(str, sizeof(str), tokens, sizeof(tokens),
		sep, sizeof(sep)), 2);
	ck_assert_token(tokens[0], str + 3, 3);
	ck_assert_token(tokens[1], str + 8, 2);
	for (size_t i = 2; i < sizeof(tokens) / sizeof(*tokens); i++)
		ck_assert_token(tokens[i], NULL, 0);
} END_TEST

void suite_tokenize(SRunner *runner) {

	Suite *suite = suite_create("tokenize");
	
	TCase *param_tc = tcase_create("param tests");
	tcase_add_test(param_tc, str_len_0_test);
	tcase_add_test(param_tc, tokens_len_0_test);
	tcase_add_test(param_tc, sep_len_0_test);
	suite_add_tcase(suite, param_tc);

	TCase *tokenize_tc = tcase_create("tokenize");
	tcase_add_checked_fixture(tokenize_tc, setup, NULL);
	tcase_add_test(tokenize_tc, tokenize_test01);
	tcase_add_test(tokenize_tc, tokenize_test02);
	tcase_add_test(tokenize_tc, tokenize_test03);
	tcase_add_test(tokenize_tc, tokenize_test04);
	tcase_add_test(tokenize_tc, tokenize_test05);
	tcase_add_test(tokenize_tc, tokenize_test06);
	tcase_add_test(tokenize_tc, tokenize_test07);
	tcase_add_test(tokenize_tc, tokenize_test100);
	tcase_add_test(tokenize_tc, tokenize_test101);
	tcase_add_test(tokenize_tc, tokenize_test102);
	tcase_add_test(tokenize_tc, tokenize_test103);
	tcase_add_test(tokenize_tc, tokenize_test104);
	tcase_add_test(tokenize_tc, tokenize_test105);
	tcase_add_test(tokenize_tc, tokenize_test106);
	tcase_add_test(tokenize_tc, tokenize_more_sep_test);
	suite_add_tcase(suite, tokenize_tc);

	srunner_add_suite(runner, suite);
}
