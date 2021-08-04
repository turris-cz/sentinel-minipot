/*
 *  Turris:Sentinel Minipot - password Honeypot
 *  Copyright (C) 2019-2020 CZ.NIC z.s.p.o. (https://www.nic.cz/)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <unistd.h>

#include "utils.h"
#include "minipot_pipe.h"

int write_all(int fd, const void *data, size_t len) {
	TRACE_FUNC_FD(fd);
	assert(fd >= 0);
	if (len > 0)
		assert(data);
	while (len > 0) {
		ssize_t sent = write(fd, data, len);
		if (sent == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			error("Couldn't write data to FD: %d", fd);
			return -1;
		}
		data += (size_t)sent;
		len -= (size_t)sent;
	}
	return 0;
}

int send_to_master(int fd, const void *data, size_t len) {
	TRACE_FUNC_FD(fd);
	assert(fd >= 0);
	if (len > 0)
		assert(data);
	// first send data length
	if (write_all(fd, &len, sizeof(len)))
		return -1;
	return write_all(fd, data, len);
}

int check_sentinel_msg(const struct sentinel_msg *msg) {
	TRACE_FUNC;
	assert(msg);
	if (msg->ts <= 0) {
		error("Proxy message has invalid time stamp field");
		return -1;
	}
	if (!msg->type || strlen(msg->type) == 0) {
		error("Proxy message has invalid type field");
		return -1;
	}
	if (!msg->ip || strlen(msg->ip) == 0) {
		error("Proxy message has invalid ip field");
		return -1;
	}
	if (!msg->action || strlen(msg->action) == 0) {
		error("Proxy message has invalid action field");
		return -1;
	}
	if (msg->data_len > 0) {
		if (!msg->data) {
			error("Proxy message has invalid action field");
			return -1;
		}
		for (size_t i = 0; i < msg->data_len; i++) {
			// key must have length at least 1
			if (!msg->data[i].key || msg->data[i].key_len < 1) {
				error("Key of proxy message data field is invalid");
				return -1;
			}
			// value can have zero length
			if (msg->data[i].val_len > 0 && !msg->data[i].val) {
				error("Value of proxy message data field is invalid");
				return -1;
			}
		}
	}
	return 0;
} 

#define PACK_STR(packer, str) do { \
	msgpack_pack_str(packer, strlen(str));\
	msgpack_pack_str_body(packer, str, strlen(str)); \
	} while(0);

int pack_sentinel_msg(msgpack_sbuffer *sbuff, msgpack_sbuffer *sbuff_data,
		const struct sentinel_msg *msg) {
	TRACE_FUNC;
	assert(sbuff);
	assert(sbuff_data);
	assert(msg);
	if (check_sentinel_msg(msg))
		return -1;

	msgpack_packer packer;	
	msgpack_packer_init(&packer, sbuff, msgpack_sbuffer_write);
	msgpack_pack_map(&packer, msg->data_len > 0 ? 5 : 4);
	PACK_STR(&packer, "ts");
	msgpack_pack_long_long(&packer, msg->ts);
	PACK_STR(&packer, "type");
	PACK_STR(&packer, msg->type);
	PACK_STR(&packer, "ip");
	PACK_STR(&packer, msg->ip);
	PACK_STR(&packer, "action");
	PACK_STR(&packer, msg->action);

	if (msg->data_len > 0) {
		msgpack_packer data_pk;
		msgpack_packer_init(&data_pk, sbuff_data, msgpack_sbuffer_write);
		msgpack_pack_map(&data_pk, msg->data_len);

		for (size_t i = 0; i < msg->data_len; i++) {
			msgpack_pack_str(&data_pk, msg->data[i].key_len);
			msgpack_pack_str_body(&data_pk, msg->data[i].key, msg->data[i].key_len);
			msgpack_pack_str(&data_pk, msg->data[i].val_len);
			msgpack_pack_str_body(&data_pk, msg->data[i].val, msg->data[i].val_len);
		}
		PACK_STR(&packer,"data");
		// pack binary without header, because the data are already serialized
		msgpack_pack_str_body(&packer, sbuff_data->data, sbuff_data->size);
	}
	return 0;
}
