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
	TRACE_FUNC_FD(fd);
	int flags;
	flags = fcntl(fd, F_GETFL);
	if (flags < 0)
		return flags;
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0) {
		error("Can't set nonblocking mode on FD: %d", fd);
		return -1;
	}
	return 0;
}

int sockaddr2str(const struct sockaddr_storage *sockaddr, char *buff) {
	TRACE_FUNC;
	assert(sockaddr);
	assert(buff);
	if (sockaddr->ss_family == AF_INET6) {
		// IPv6
		const struct sockaddr_in6 *ip_v6_sockaddr =
			(const struct sockaddr_in6 *)sockaddr;
		const struct in6_addr *addr = &(ip_v6_sockaddr->sin6_addr);
		if (addr->s6_addr32[0] == 0 && addr->s6_addr32[1] == 0 &&
			addr->s6_addr16[4] == 0 && addr->s6_addr16[5] == 0xFFFF)
			// IPv4 mapped on IPv6 address with format 0:0:FFFF:<IPv4-address>
			inet_ntop(AF_INET, &addr->s6_addr32[3], buff, INET_ADDRSTRLEN);
		else
			// normal IPv6 address
			inet_ntop(AF_INET6, addr, buff, INET6_ADDRSTRLEN);
	} else if (sockaddr->ss_family == AF_INET) {
		// IPv4
		const struct sockaddr_in *ip_v4_sockaddr =
			(const struct sockaddr_in *)sockaddr;
		inet_ntop(AF_INET, &ip_v4_sockaddr->sin_addr, buff, INET_ADDRSTRLEN);
	} else {
		error("Couldn't get IP adress from unsupported socket family type: %d",
			sockaddr->ss_family);
		return -1;
	}
	return 0;
}

int send_all(int fd, const char *data, size_t amount) {
	TRACE_FUNC_FD(fd);
	while (amount > 0) {
		ssize_t sent = send(fd, data, amount, MSG_NOSIGNAL);
		if (sent == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			info("Couldn't send data to FD: %d", fd);
			return -1;
		}
		data += (size_t)sent;
		amount -= (size_t)sent;
	}
	return 0;
}

const uint8_t *skip_sel_bytes(const uint8_t *str, size_t str_len,
		const uint8_t *to_skip, size_t to_skip_len) {
	TRACE_FUNC;
	assert(str);
	assert(to_skip);
	const uint8_t *end_ptr = str + str_len;
cont:
	while (str < end_ptr) {
		for (size_t i = 0; i < to_skip_len; i++)
			if (*str == to_skip[i]) {
				str++;
				goto cont;
			}
		break;
	}
	return str;
}

const uint8_t *find_first_occur(const uint8_t *str, size_t str_len,
		const uint8_t *find, size_t find_len) {
	TRACE_FUNC;
	assert(str);
	assert(find);
	const uint8_t *end_ptr = str + str_len;
	while (str < end_ptr) {
		for (size_t i = 0; i < find_len; i++)
			if (*str == find[i])
				return str;
		str++;
	}
	return str;
}

size_t tokenize(const uint8_t *str, size_t str_len, struct token *tokens,
		size_t tokens_len, const uint8_t *separators, size_t sep_len) {
	TRACE_FUNC;
	assert(str);
	assert(tokens);
	assert(separators);

	size_t tokens_cnt = 0;
	const uint8_t *str_end = str + str_len;
	const uint8_t *token_start = str;
	size_t token_len = str_len;

	for (size_t i = 0; i < tokens_len; i++) {
		token_start = skip_sel_bytes(token_start, token_len, separators, sep_len);
		if (token_start == str_end)
			break;
		token_len = str_end - token_start;
		const uint8_t *token_end = find_first_occur(token_start, token_len,
			separators, sep_len);
		// fill token
		tokens_cnt++;
		tokens[i].start_ptr = token_start;
		tokens[i].len = token_end - token_start;
		if (token_end == str_end)
			break;
		token_start = token_end;
	}
	return tokens_cnt;
}

void ev_base_discard_cb(int severity, const char *msg) {}

void on_sigint(evutil_socket_t sig, short events, void *user_data) {
	errno = 0;
	TRACE_FUNC;
	struct event_base *evb = (struct event_base *)user_data;
	event_base_loopbreak(evb);
}

void concat_str(char **buff, size_t args_num, ...) {
	TRACE_FUNC;
	assert(buff);
	size_t len = 0;
	FILE *tmp = open_memstream(buff, &len);
	if (!tmp)
		return;
	va_list args;
	va_start(args, args_num);
	for (size_t i = 0; i < args_num; i++) {
		char *arg = va_arg(args, char*);
		fwrite(arg, sizeof(*arg), strlen(arg), tmp);
	}
	va_end(args);
	fclose(tmp);
}

int check_serv_data(const uint8_t *buff, size_t len) {
	TRACE_FUNC;
	if (len > 0)
		assert(buff);
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
	// check if the string is complete
	if (state == S0)
		return 0;
	return -1;
}
