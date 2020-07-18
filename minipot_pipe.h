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

#include <stdlib.h>
#include <stdint.h>

struct uint8_t_pair {
	uint8_t *key;
	size_t key_len;
	uint8_t *val;
	size_t val_len;
};

struct proxy_data {
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

int proxy_report(int pipe_fd, struct proxy_data *proxy_data);

#endif /*__SENTINEL_MINIPOT_PIPE_H__*/
