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
	while (len > 0) {
		ssize_t sent = write(fd, data, len);
		if (sent == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
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

int proxy_report(int pipe_fd, struct proxy_data *proxy_data) {
	if (!proxy_data || pipe_fd < 0) {
		DEBUG_PRINT("proxy report - wrong arguments\n");
		return -1;
	}
	msgpack_sbuffer sbuf;
	msgpack_packer pk;
	msgpack_sbuffer_init(&sbuf);
	msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
	// ts, type, action, ip are mandatory
	// data are optional
	size_t valid_data_len = 0;
	if (proxy_data->data) {
		for (size_t i = 0; i < proxy_data->data_len; i++)
			if (proxy_data->data[i].key && proxy_data->data[i].val &&
				proxy_data->data[i].key_len >= 1 && proxy_data->data[i].val_len >= 1)
				valid_data_len++;
	}
	size_t map_size = (valid_data_len > 0) ? 5 : 4;
	msgpack_pack_map(&pk, map_size);
	if (proxy_data->ts) {
		PACK_STR(&pk, "ts");
		msgpack_pack_long_long(&pk, proxy_data->ts);
	} else {
		DEBUG_PRINT("proxy report - wrong ts\n");
		DES_AND_RET(&sbuf);
	}
	if (proxy_data->type) {
		PACK_STR(&pk, "type");
		PACK_STR(&pk, proxy_data->type);
	} else {
		DEBUG_PRINT("proxy report - wrong type\n");
		DES_AND_RET(&sbuf);
	}
	if (proxy_data->ip) {
		PACK_STR(&pk, "ip");
		PACK_STR(&pk, proxy_data->ip);
	} else {
		DEBUG_PRINT("proxy report - wrong ip\n");
		DES_AND_RET(&sbuf);
	}
	if (proxy_data->action) {
		PACK_STR(&pk, "action");
		PACK_STR(&pk, proxy_data->action);
	} else {
		DEBUG_PRINT("proxy report - wrong action\n");
		DES_AND_RET(&sbuf);
	}
	if (valid_data_len > 0) {
		// pack valid data if any
		msgpack_sbuffer data_sbuf;
		msgpack_packer data_pk;
		msgpack_sbuffer_init(&data_sbuf);
		msgpack_packer_init(&data_pk, &data_sbuf, msgpack_sbuffer_write);
		msgpack_pack_map(&data_pk, valid_data_len);
		for (size_t i = 0; i < proxy_data->data_len; i++)
			if (proxy_data->data[i].key && proxy_data->data[i].val &&
				proxy_data->data[i].key_len >= 1 && proxy_data->data[i].val_len >= 1) {
				msgpack_pack_str(&data_pk, proxy_data->data[i].key_len);
				msgpack_pack_str_body(&data_pk, proxy_data->data[i].key, proxy_data->data[i].key_len);
				msgpack_pack_str(&data_pk, proxy_data->data[i].val_len);
				msgpack_pack_str_body(&data_pk, proxy_data->data[i].val, proxy_data->data[i].val_len);
			}
		PACK_STR(&pk,"data");
		// normally, one would expect msgpack_pack_bin(&pk, messages[i].len) here - to append header for the binary
		// but we don't want that here - Data received already have its header. Doing that would result in corrupt msgpack.
		// just pack binary, without header
		msgpack_pack_str_body(&pk, data_sbuf.data, data_sbuf.size);
		msgpack_sbuffer_destroy(&data_sbuf);
	}
	// send data length
	if (write_all(pipe_fd, &sbuf.size, sizeof(sbuf.size)) != 0) {
		DEBUG_PRINT("proxy report - could not write data to pipe\n");
		DES_AND_RET(&sbuf);
	}
	// send data
	if (write_all(pipe_fd, sbuf.data, sbuf.size) != 0) {
		DEBUG_PRINT("proxy report - could not write data to pipe\n");
		DES_AND_RET(&sbuf);
	}
	msgpack_sbuffer_destroy(&sbuf);
	return 0;
}
