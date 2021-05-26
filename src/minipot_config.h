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

#ifndef __SENTINEL_MINIPOT_CONFIG_H__
#define __SENTINEL_MINIPOT_CONFIG_H__

#include <stdint.h>

#define DEFAULT_LOCAL_SOCKET "ipc:///tmp/sentinel_pull.sock"
#define DEFAULT_TOPIC "sentinel/collect/minipot"
#define DEFAULT_USER "nobody"
#define MAX_MINIPOT_COUNT 10

enum minipot_error {
	MP_ERR_OK,
	MP_ERR_CLI,
	MP_ERR_CHILD,
	MP_ERR_SERVICE,
	MP_ERR_PROXY_CONN,
	MP_ERR_PIPE_MALLOC,
	MP_ERR_PROXY_SENT,
	MP_ERR_PIPE_READ,
	MP_ERR_PIPE_PROTOCOL,
	MP_ERR_NUM_CODES // number of minipot errors
};

enum minipot_type {
	MP_TYPE_FTP,
	MP_TYPE_HTTP,
	MP_TYPE_SMTP,
	MP_TYPE_TELNET,
	MP_TYPE_NUM_TYPES //number of minipot types
};

struct minipot_conf {
	uint16_t port;
	enum minipot_type type;
};

struct configuration {
	const char *user;
	const char *topic;
	const char *socket;
	size_t minipots_count;
	struct minipot_conf minipots_conf[MAX_MINIPOT_COUNT];
};

#endif /*__SENTINEL_MINIPOT_CONFIG_H__*/
