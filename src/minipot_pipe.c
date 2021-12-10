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
#include <errno.h>
#include <msgpack.h>

#include "minipot_pipe.h"
#include "utils.h"

static int write_all(int fd, const void *data, size_t len) {
	TRACE_FUNC_FD(fd);
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

#define PACK_STR(packer, str) do { \
	msgpack_pack_str(packer, strlen(str));\
	msgpack_pack_str_body(packer, str, strlen(str)); \
	} while(0);

#define DES_AND_RET(sbuf) do { \
	msgpack_sbuffer_destroy(sbuf); \
	return -1; \
	} while (0)

int proxy_report(int pipe_fd, struct proxy_msg *proxy_msg) {
	TRACE_FUNC_FD(pipe_fd);
	if (!proxy_msg || pipe_fd < 0) {
		error("Invalid arguments passed to proxy_report");
		return -1;
	}
	msgpack_sbuffer sbuf;
	msgpack_packer pk;
	msgpack_sbuffer_init(&sbuf);
	msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
	// ts, type, action, ip are mandatory
	// data are optional
	size_t map_size = (proxy_msg->data_len > 0) ? 5 : 4;
	msgpack_pack_map(&pk, map_size);
	if (proxy_msg->ts) {
		PACK_STR(&pk, "ts");
		msgpack_pack_long_long(&pk, proxy_msg->ts);
	} else {
		error("Proxy message has invalid time stamp field");
		DES_AND_RET(&sbuf);
	}
	if (proxy_msg->type) {
		PACK_STR(&pk, "type");
		PACK_STR(&pk, proxy_msg->type);
	} else {
		error("Proxy message has invalid type field");
		DES_AND_RET(&sbuf);
	}
	if (proxy_msg->ip) {
		PACK_STR(&pk, "ip");
		PACK_STR(&pk, proxy_msg->ip);
	} else {
		error("Proxy message has invalid ip field");
		DES_AND_RET(&sbuf);
	}
	if (proxy_msg->action) {
		PACK_STR(&pk, "action");
		PACK_STR(&pk, proxy_msg->action);
	} else {
		error("Proxy message has invalid action field");
		DES_AND_RET(&sbuf);
	}
	if (proxy_msg->data_len > 0) {
		if (proxy_msg->data == NULL) {
			error("Proxy message has invalid data field");
			DES_AND_RET(&sbuf);
		}
		msgpack_sbuffer data_sbuf;
		msgpack_packer data_pk;
		msgpack_sbuffer_init(&data_sbuf);
		msgpack_packer_init(&data_pk, &data_sbuf, msgpack_sbuffer_write);
		msgpack_pack_map(&data_pk, proxy_msg->data_len);

		for (size_t i = 0; i < proxy_msg->data_len; i++) {
				// key must have length at least 1
				if (proxy_msg->data[i].key_len < 1 || proxy_msg->data[i].key == NULL) {
					error("Key of proxy message data field is invalid");
					DES_AND_RET(&data_sbuf);
					DES_AND_RET(&sbuf);
				}
				msgpack_pack_str(&data_pk, proxy_msg->data[i].key_len);
				msgpack_pack_str_body(&data_pk, proxy_msg->data[i].key, proxy_msg->data[i].key_len);
				// value can have zero length
				if (proxy_msg->data[i].val_len > 0 && proxy_msg->data[i].val == NULL) {
					error("Data of proxy message data field is invalid");
					DES_AND_RET(&data_sbuf);
					DES_AND_RET(&sbuf);
				}
				msgpack_pack_str(&data_pk, proxy_msg->data[i].val_len);
				msgpack_pack_str_body(&data_pk, proxy_msg->data[i].val, proxy_msg->data[i].val_len);
		}
		PACK_STR(&pk,"data");
		// pack binary without header, because the data are already serialized
		msgpack_pack_str_body(&pk, data_sbuf.data, data_sbuf.size);
		msgpack_sbuffer_destroy(&data_sbuf);
	}
	// send data length
	if (write_all(pipe_fd, &sbuf.size, sizeof(sbuf.size)))
		DES_AND_RET(&sbuf);
	// send data
	if (write_all(pipe_fd, sbuf.data, sbuf.size))
		DES_AND_RET(&sbuf);
	msgpack_sbuffer_destroy(&sbuf);
	return 0;
}