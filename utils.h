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

#ifndef __SENTINEL_MINIPOT_UTILS_H__
#define __SENTINEL_MINIPOT_UTILS_H__

#include <stdio.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
#include <event.h>

#define IP_ADDR_LEN INET6_ADDRSTRLEN

#define DEBUG 1

#ifdef DEBUG
#define DEBUG_PRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_PRINT(...) do { } while (0);
#endif

#ifdef DEBUG
#define DEBUG_WRITE(...) do { \
	fwrite(__VA_ARGS__, stderr); \
	fprintf(stderr, "\n"); \
	} while (0)
#else
#define DEBUG_WRITE(...) do { } while (0);
#endif

#define FLOW_GUARD(cmd) do { \
	if (cmd) \
		return -1; \
	} while (0)

#define MY_MIN(a,b) \
   ({ __typeof__ (a) _a = (a); \
	   __typeof__ (b) _b = (b); \
	 _a > _b ? _b : _a; })

#define SIZEOF_MEMBER(TYPE, MEMBER) sizeof(((TYPE*)NULL)->MEMBER)
#define TYPEOF_MEMBER(TYPE, MEMBER) __typeof__(((TYPE*)NULL)->MEMBER)

struct token{
	uint8_t *start_ptr;
	size_t len;
};

int setnonblock(int fd);
int sockaddr_to_string(struct sockaddr_storage *conn_addr, char *str);
int send_all(int fd, const char *data, size_t amount);

/**
 * tokenize - Splits string (NOT NULL TERMINATED C-STRING) into tokens according to given separators.
 * 			There can be more separators between two tokens. Each token in saved in output array of token structs.
 * @str: start pointer to byte array
 * @str_len: length of byte array
 * @tokens: start pointer to array of token structs
 * @tokens_len: length of token structs array
 * @separators: start pointer to array of bytes
 * 				Each byte is considered as a separator.
 * @sep_len: length of byte array defined by @separators
 */
size_t tokenize(uint8_t *str, size_t str_len, struct token *tokens, size_t tokens_len, uint8_t *separators, size_t sep_len);
void ev_base_discard_cb(int severity, const char *msg);
void concat_mesg(char **buff, size_t args_num, ...);
void on_sigint(evutil_socket_t sig, short events, void *user_data);

#endif /*__SENTINEL_MINIPOT_UTILS_H__*/
