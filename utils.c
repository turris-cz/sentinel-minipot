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
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <event.h>

#include "utils.h"

int setnonblock(int fd) {
	int flags;
	flags = fcntl(fd, F_GETFL);
	if (flags < 0)
		return flags;
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0)
		return -1;
	return 0;
}

int sockaddr_to_string(struct sockaddr_storage *conn_addr, char *str) {
	if (conn_addr->ss_family == AF_INET6) {
		// IPv6
		struct sockaddr_in6 *connection_addr6 = (struct sockaddr_in6 *)conn_addr;
		struct in6_addr *v6 = &(connection_addr6->sin6_addr);
		if (v6->s6_addr32[0] == 0 && v6->s6_addr32[1] == 0 &&
			v6->s6_addr16[4] == 0 && v6->s6_addr16[5] == 0xFFFF)
			inet_ntop(AF_INET, &v6->s6_addr32[3], str, INET_ADDRSTRLEN);
		else
			inet_ntop(AF_INET6, v6, str, INET6_ADDRSTRLEN);
		return 0;
	} else if (conn_addr->ss_family == AF_INET) {
		// IPv4
		struct sockaddr_in *connection_addr4 = (struct sockaddr_in *)conn_addr;
		inet_ntop(AF_INET, &connection_addr4->sin_addr, str, INET_ADDRSTRLEN);
		return 0;
	} else {
		return 1;
	}
}

int send_all(int fd, const char *data, size_t amount) {
	while (amount > 0) {
		ssize_t sent = send(fd, data, amount, MSG_NOSIGNAL);
		if (sent == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			return -1;
		}
		data += (size_t)sent;
		amount -= (size_t)sent;
	}
	return 0;
}

// Skips given bytes from given string starting at first byte of the string.
// str: pointer to the string
// str_len: length of the string
// to_skip: pointer to array of bytes/chars to be skipped
// 		Each byte/char is going to be skipped.
// to_skip_len: length of to_skip array
// If str_len is 0 or to_skip_len is 0 or str is NULL or to_skip is NULL, str
// is returned. Returns pointer to first byte in string not contained in bytes
// to skip. If all bytes/chars are skipped it returns pointer to the last
// character of the string.
static uint8_t *skip_sel_bytes(uint8_t *str, size_t str_len, uint8_t *to_skip, size_t to_skip_len) {
	if (!str || str_len == 0 || !to_skip || to_skip_len == 0) {
		DEBUG_PRINT("http - skip bytes - wrong input\n");
		return str;
	}
	uint8_t *end_ptr = str + str_len;
	main:
	while (str < end_ptr) {
		for (size_t i = 0; i < to_skip_len; i++) {
			if (*str == to_skip[i]) {
				str++;
				goto main;
			}
		}
		break;
	}
	if (str == end_ptr)
		return str -1;
	else
		return str;
}

// Finds first occurence of given bytes in given string.
// str: pointer to the string
// str_len: length of the string
// to_skip: pointer to array of bytes/chars to be searched for
// 		 Presence of each byte/char is going to be evaluated.
// Returns pointer to first character in the string matching any byte from
// to_skip. If str is NULL or to_skip is NULL or str_len is 0 or to_skip_len is
// 0, it returns NULL. If NO occurance of evaluated bytes is found, it returns NULL.
static uint8_t *find_first_occur(uint8_t *str, size_t str_len, uint8_t *to_skip, size_t to_skip_len) {
	if (!str || str_len == 0 || !to_skip || to_skip_len == 0) {
		DEBUG_PRINT("http - find first occur - wrong input\n");
		return NULL;
	}
	uint8_t *end_ptr = str + str_len;
	while (str < end_ptr) {
		for (size_t i = 0; i < to_skip_len; i++) {
			if (*str == to_skip[i]) {
				return str;
			}
		}
		str++;
	}
	return NULL;
}

size_t tokenize(uint8_t *str, size_t str_len, struct token *tokens, size_t tokens_len, uint8_t *separators, size_t sep_len) {
	DEBUG_PRINT("tokenize\n");
	uint8_t *str_end = str + str_len - 1;
	uint8_t *token_start = str;
	size_t tokens_cnt = 0;
	for (size_t i = 0; i < tokens_len; i++) {
		token_start = skip_sel_bytes(token_start, str_end - token_start + 1, separators, sep_len);
		if (token_start == str_end) {
			// check last byte
			for (size_t j = 0; j < sep_len; j++) {
				if (*token_start == separators[j]) {
					// no more tokens
					return tokens_cnt;
				}
			}
			// token of len 1 at the end of buffer
			tokens_cnt++;
			tokens[i].start_ptr = token_start;
			tokens[i].len = 1;
			return tokens_cnt;

		} else {
			// token
			tokens_cnt++;
			tokens[i].start_ptr = token_start;
			uint8_t *first_ps_after_token = find_first_occur(token_start, str_end - token_start + 1, separators, sep_len);
			if (first_ps_after_token != NULL) {
				// maybe more tokens
				tokens[i].len = first_ps_after_token - token_start;
				token_start = first_ps_after_token;
			} else {
				// no more tokens
				tokens[i].len = str_end - token_start + 1;
				return tokens_cnt;
			}
		}
	}
	DEBUG_PRINT("tokenize - reached maximum tokens\n");
}

void ev_base_discard_cb(int severity, const char *msg) {}

void on_sigint(evutil_socket_t sig, short events, void *user_data) {
	struct event_base *evb = (struct event_base *)user_data;
	event_base_loopbreak(evb);
}

void concat_mesg(char **buff, size_t args_num, ...) {
	DEBUG_PRINT("utils - concat mesg\n");
	va_list args;
	size_t mesg_size = 0;
	va_start(args, args_num);
	for (size_t i = 0; i < args_num; i++)
		mesg_size += strlen(va_arg(args, char*));
	va_end(args);
	mesg_size++; // terminating null byte

	*buff = malloc(mesg_size);
	**buff = 0;
	va_start(args, args_num);
	for (size_t i = 0; i < args_num; i++)
		strcat(*buff, va_arg(args, char*));
	va_end(args);
}

int check_serv_data(const uint8_t *buff, size_t len) {
	DEBUG_PRINT("utils - check_serv_data\n");
	enum state{S0, S1, S2, S3, S4, S5, S6, S7} state = S0;
	for (size_t i = 0; i < len; i++) {
		switch (state) {
			case S0:
				if (buff[i] >= 1 && buff[i] <= 127)
					; // stay at current state
				else if (buff[i] >= 194 && buff[i] <= 223)
					state = S1;
				else if (buff[i] == 224)
					state = S2;
				else if ((buff[i] >= 225 && buff[i] <= 236) ||
					(buff[i] >= 238 && buff[i] <= 239))
					state = S3;
				else if (buff[i] == 237)
					state = S4;
				else if (buff[i] == 240)
					state = S5;
				else if (buff[i] >= 241 && buff[i] <= 243)
					state = S6;
				else if (buff[i] == 244)
					state = S7;
				else
					return -1;
				break;
			case S1:
				if (buff[i] >= 128 && buff[i] <= 191)
					state = S0;
				else
					return -1;
				break;
			case S2:
				if (buff[i] >= 160 && buff[i] <= 191)
					state = S1;
				else
					return -1;
				break;
			case S3:
				if (buff[i] >= 128 && buff[i] <= 191)
					state = S1;
				else
					return -1;
				break;
			case S4:
				if (buff[i] >= 128 && buff[i] <= 159)
					state = S1;
				else
					return -1;
				break;
			case S5:
				if (buff[i] >= 144 && buff[i] <= 191)
					state = S3;
				else
					return -1;
				break;
			case S6:
				if (buff[i] >= 128 && buff[i] <= 191)
					state = S3;
				else
					return -1;
				break;
			case S7:
				if (buff[i] >= 128 && buff[i] <= 143)
					state = S3;
				else
					return -1;
				break;
		}
	}
	DEBUG_PRINT("state: %d\n",state);
	// check if the string is complete
	if (state == S0) {
		DEBUG_PRINT("utf-8 passed\n");
		return 0;
	} else {
		DEBUG_PRINT("utf-8 failed\n");
		return -1;
	}
}
