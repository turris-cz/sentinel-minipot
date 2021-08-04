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

#ifndef __SENTINEL_MINIPOT_PIPE_H__
#define __SENTINEL_MINIPOT_PIPE_H__

#include <msgpack.h>

struct uint8_t_pair {
	uint8_t *key;
	size_t key_len;
	uint8_t *val;
	size_t val_len;
};

struct sentinel_msg {
	// these fields are mandatory
	long long int ts;
	// these MUST be NULL terminated strings
	char *type;
	char *ip;
	char *action;
	// optional data
	// these are from attacker
	struct uint8_t_pair *data;
	size_t data_len;
};

// Returns 0 if passed sentinel massage is correctly filled with data.
// If NOT it returns -1.
int check_sentinel_msg(const struct sentinel_msg *msg);

// Sends data to master process. If success returns 0 otherwise -1.
int send_to_master(int fd, const void *data, size_t len);

// Msgpacks sentinel message to passed buffers. It first checks the message
// by calling check_sentinel_msg(). If check failed returns -1 and without
// packing. If message check passes it packs the data and returns 0.
int pack_sentinel_msg(msgpack_sbuffer *sbuff, msgpack_sbuffer *sbuff_data,
	const struct sentinel_msg *msg);

#endif /*__SENTINEL_MINIPOT_PIPE_H__*/
