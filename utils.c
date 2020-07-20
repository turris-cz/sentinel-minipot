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

/* Sends amount of data to a socket fd. If successful returns 0 othervise -1. */
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

/* Finds a first occurence of any byte (defined by to_skip pointer and length) in str (defined by str pointer and its length).
If NO occurance is found returns NULL.
If input pointers are NULL or lengths are 0 also retuns NULL.
 */
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

void ev_base_discard_cb(int severity, const char *msg) {
	/* This callback does nothing. */
}

void on_sigint(evutil_socket_t sig, short events, void *user_data) {
	struct event_base *evb = (struct event_base *)user_data;
	event_base_loopbreak(evb);
}

/*
 * Returns true if char is valid base64 char and false if it is not.
 * Does NOT check for PADDING char, because it can be only at 2 last positions!
 */
static bool base64_is_valid_mid_char(const char c) {
	return \
		(c >= '0' && c <= '9') || \
		(c >= 'A' && c <= 'Z') || \
		(c >= 'a' && c <= 'z') || \
		(c == '+' || c == '/');
}

static bool base64_is_valid_mid_string(const char *const data, size_t len) {
	for (size_t i = 0; i < len; i++)
		if (!base64_is_valid_mid_char(data[i]))
			return false;
	return true;
}

/*
 * Returns true if data is valid base64 string and false otherwise.
 * Doesn't need nor verifies null terminating byte.
 * Input is treated as byte array.
 */
bool base64_is_valid(const char *const data, size_t len) {
	/* Minimum size of the data is 4 chars with two == as padding
	or 2 chars without the padding.
	The padding is in some cases ignored.
	*/
	if (len == 1)
		return false;

	int padding = 0;
	if (len > 2)
		for (; padding < 2 && data[len - padding - 1] == '='; padding++);

	return base64_is_valid_mid_string(data, len - padding);
}

/*
 * Allocates memory and concats null terminated strings to one null terminated string.
 */
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

int setup_sock(int *fd) {
	*fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (*fd == -1)
		return -1;

	int flag = 1;
	if (setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) != 0)
		goto err;
	flag = 0;
	if (setsockopt(*fd, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag)) != 0)
		goto err;
	if (setnonblock(*fd) != 0)
		goto err;
	return 0;

err:
	close(*fd);
	return -1;
}

int bind_to_port(int fd, uint16_t port) {
	struct sockaddr_in6 listen_addr;
	memset(&listen_addr, 0, sizeof(listen_addr));
	listen_addr.sin6_family = AF_INET6;
	listen_addr.sin6_addr = in6addr_any;
	listen_addr.sin6_port = htons(port);
	if (bind(fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) != 0)
		return -1;
	return 0;
}
