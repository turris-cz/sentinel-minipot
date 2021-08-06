#include <check.h>
#include "../../src/minipot_pipe.h"

#define STR "ahddds"

static msgpack_sbuffer sbuff;
static msgpack_sbuffer sbuff_data;
static msgpack_unpacked upkd;

static void setup() {
	msgpack_sbuffer_init(&sbuff_data);
	msgpack_sbuffer_init(&sbuff);
	msgpack_unpacked_init(&upkd);
}

static void teardown() {
	msgpack_sbuffer_destroy(&sbuff_data);
	msgpack_sbuffer_destroy(&sbuff);
	msgpack_unpacked_destroy(&upkd);
}

#define ck_assert_msgpack_str(msgpack, string) do { \
		ck_assert_int_eq(msgpack.type, MSGPACK_OBJECT_STR); \
		ck_assert_int_eq(msgpack.via.str.size, strlen(string)); \
		ck_assert_mem_eq(msgpack.via.str.ptr, string, strlen(string)); \
	} while (false)

#define ck_assert_msgpack_uint(msgpack, num) do { \
		ck_assert_int_eq(msgpack.type, MSGPACK_OBJECT_POSITIVE_INTEGER); \
		ck_assert_int_eq(msgpack.via.u64, num); \
	} while (false)


START_TEST(pack_test01) {
	struct sentinel_msg msg = {
		.action = "a", .ip = "b", .type = "q", .ts = 1,
	};
	ck_assert_int_eq(pack_sentinel_msg(&sbuff, &sbuff_data, &msg), 0);
	ck_assert_int_eq(msgpack_unpack_next(&upkd, sbuff.data, sbuff.size, NULL),
		MSGPACK_UNPACK_SUCCESS);
	msgpack_object r = upkd.data;
	ck_assert_int_eq(r.type, MSGPACK_OBJECT_MAP);
	ck_assert_int_eq(r.via.map.size, 4);
	ck_assert_msgpack_str(r.via.map.ptr[0].key, "ts");
	ck_assert_msgpack_uint(r.via.map.ptr[0].val, msg.ts);

	ck_assert_msgpack_str(r.via.map.ptr[1].key, "type");
	ck_assert_msgpack_str(r.via.map.ptr[1].val, msg.type);
	
	ck_assert_msgpack_str(r.via.map.ptr[2].key, "ip");
	ck_assert_msgpack_str(r.via.map.ptr[2].val, msg.ip);
	
	ck_assert_msgpack_str(r.via.map.ptr[3].key, "action");
	ck_assert_msgpack_str(r.via.map.ptr[3].val, msg.action);
	
} END_TEST


START_TEST(pack_test02) {
	struct uint8_t_pair data = {
		.key = STR, .key_len = strlen(STR), .val = STR, .val_len = strlen(STR)
	};
	struct sentinel_msg msg = {
		.action = "a", .ip = "b", .type = "q", .ts = 1, .data = &data,
		.data_len = 1
	};
	ck_assert_int_eq(pack_sentinel_msg(&sbuff, &sbuff_data, &msg), 0);
	ck_assert_int_eq(msgpack_unpack_next(&upkd, sbuff.data, sbuff.size, NULL),
		MSGPACK_UNPACK_SUCCESS);
	msgpack_object r = upkd.data;
	ck_assert_int_eq(r.type, MSGPACK_OBJECT_MAP);
	ck_assert_int_eq(r.via.map.size, 5);
	ck_assert_msgpack_str(r.via.map.ptr[0].key, "ts");
	ck_assert_msgpack_uint(r.via.map.ptr[0].val, msg.ts);

	ck_assert_msgpack_str(r.via.map.ptr[1].key, "type");
	ck_assert_msgpack_str(r.via.map.ptr[1].val, msg.type);
	
	ck_assert_msgpack_str(r.via.map.ptr[2].key, "ip");
	ck_assert_msgpack_str(r.via.map.ptr[2].val, msg.ip);
	
	ck_assert_msgpack_str(r.via.map.ptr[3].key, "action");
	ck_assert_msgpack_str(r.via.map.ptr[3].val, msg.action);

	ck_assert_msgpack_str(r.via.map.ptr[4].key, "data");
	ck_assert_int_eq(r.via.map.ptr[4].val.type, MSGPACK_OBJECT_MAP);
	ck_assert_int_eq(r.via.map.ptr[4].val.via.map.size, 1);
	ck_assert_msgpack_str(r.via.map.ptr[4].val.via.map.ptr[0].key, STR);
	ck_assert_msgpack_str(r.via.map.ptr[4].val.via.map.ptr[0].val, STR);
	

} END_TEST

START_TEST(pack_test03) {
	struct uint8_t_pair data = {
		.key = STR, .key_len = strlen(STR), .val = NULL, .val_len = 0
	};
	struct sentinel_msg msg = {
		.action = "a", .ip = "b", .type = "q", .ts = 1, .data = &data,
		.data_len = 1
	};
	ck_assert_int_eq(pack_sentinel_msg(&sbuff, &sbuff_data, &msg), 0);
	ck_assert_int_eq(msgpack_unpack_next(&upkd, sbuff.data, sbuff.size, NULL),
		MSGPACK_UNPACK_SUCCESS);
	msgpack_object r = upkd.data;
	ck_assert_int_eq(r.type, MSGPACK_OBJECT_MAP);
	ck_assert_int_eq(r.via.map.size, 5);
	ck_assert_msgpack_str(r.via.map.ptr[0].key, "ts");
	ck_assert_msgpack_uint(r.via.map.ptr[0].val, msg.ts);

	ck_assert_msgpack_str(r.via.map.ptr[1].key, "type");
	ck_assert_msgpack_str(r.via.map.ptr[1].val, msg.type);
	
	ck_assert_msgpack_str(r.via.map.ptr[2].key, "ip");
	ck_assert_msgpack_str(r.via.map.ptr[2].val, msg.ip);
	
	ck_assert_msgpack_str(r.via.map.ptr[3].key, "action");
	ck_assert_msgpack_str(r.via.map.ptr[3].val, msg.action);

	ck_assert_msgpack_str(r.via.map.ptr[4].key, "data");
	ck_assert_int_eq(r.via.map.ptr[4].val.type, MSGPACK_OBJECT_MAP);
	ck_assert_int_eq(r.via.map.ptr[4].val.via.map.size, 1);
	ck_assert_msgpack_str(r.via.map.ptr[4].val.via.map.ptr[0].key, STR);
	ck_assert_msgpack_str(r.via.map.ptr[4].val.via.map.ptr[0].val, "");
	
} END_TEST

START_TEST(pack_test04) {
	struct uint8_t_pair data[] = {
		{.key = STR, .key_len = strlen(STR), .val = STR, .val_len = strlen(STR)},
		{.key = STR, .key_len = strlen(STR), .val = STR, .val_len = strlen(STR)},
	};
	struct sentinel_msg msg = {
		.action = "a", .ip = "b", .type = "q", .ts = 1, .data = data,
		.data_len = 2
	};
	ck_assert_int_eq(pack_sentinel_msg(&sbuff, &sbuff_data, &msg), 0);
	ck_assert_int_eq(msgpack_unpack_next(&upkd, sbuff.data, sbuff.size, NULL),
		MSGPACK_UNPACK_SUCCESS);
	msgpack_object r = upkd.data;
	ck_assert_int_eq(r.type, MSGPACK_OBJECT_MAP);
	ck_assert_int_eq(r.via.map.size, 5);
	ck_assert_msgpack_str(r.via.map.ptr[0].key, "ts");
	ck_assert_msgpack_uint(r.via.map.ptr[0].val, msg.ts);

	ck_assert_msgpack_str(r.via.map.ptr[1].key, "type");
	ck_assert_msgpack_str(r.via.map.ptr[1].val, msg.type);
	
	ck_assert_msgpack_str(r.via.map.ptr[2].key, "ip");
	ck_assert_msgpack_str(r.via.map.ptr[2].val, msg.ip);
	
	ck_assert_msgpack_str(r.via.map.ptr[3].key, "action");
	ck_assert_msgpack_str(r.via.map.ptr[3].val, msg.action);

	ck_assert_msgpack_str(r.via.map.ptr[4].key, "data");
	ck_assert_int_eq(r.via.map.ptr[4].val.type, MSGPACK_OBJECT_MAP);
	ck_assert_int_eq(r.via.map.ptr[4].val.via.map.size, 2);
	ck_assert_msgpack_str(r.via.map.ptr[4].val.via.map.ptr[0].key, STR);
	ck_assert_msgpack_str(r.via.map.ptr[4].val.via.map.ptr[0].val, STR);
	ck_assert_msgpack_str(r.via.map.ptr[4].val.via.map.ptr[1].key, STR);
	ck_assert_msgpack_str(r.via.map.ptr[4].val.via.map.ptr[1].val, STR);
	
} END_TEST



void suite_pack_sentinel_msg(SRunner *runner) {

	Suite *suite = suite_create("pack_sentinel_msg");

	TCase *pack_tc = tcase_create("pack");
	tcase_add_checked_fixture(pack_tc, setup, teardown);
	tcase_add_test(pack_tc, pack_test01);
	tcase_add_test(pack_tc, pack_test02);
	tcase_add_test(pack_tc, pack_test03);
	tcase_add_test(pack_tc, pack_test04);
	suite_add_tcase(suite, pack_tc);

	srunner_add_suite(runner, suite);
}

