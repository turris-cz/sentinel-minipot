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

#include "log.h"

#define IP_ADDR_LEN INET6_ADDRSTRLEN

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

#define TRACE_FUNC trace(__func__)
#define TRACE_FUNC_FD(fd) trace("%s (FD: %d)", __func__, fd)
#define TRACE_FUNC_P(FORMAT, ...) trace("%s (" FORMAT ")", __func__, __VA_ARGS__)

struct token{
	uint8_t *start_ptr;
	size_t len;
};

// Sets file descriptor as nonblocking.
// fd: file descriptor
// Returns 0 if setting was sucessfull otherwise -1 is returned.
int setnonblock(int fd);

// Extracts IP adress from socket adress storage and stores it at buffer.
// conn_addr: pointer to socket_addr_storage struct
// str: pointer to the buffer
// Caller is responsible for proper memory allocation and free of str buffer.
// It is highly recomended to use IP_ADDR_LEN macro for the buffer allocation.
// Returns 0 if IPv4 or IPv6 adress was extracted to the buffer otherwise 1 is
// returned.
int sockaddr_to_string(struct sockaddr_storage *conn_addr, char *str);

// Sends data to a socket.
// fd: socket FD
// data: pointer to data
// amount: length of the data
// If successful returns 0 othervise -1.
int send_all(int fd, const char *data, size_t amount);

// Skips given bytes from given string starting at first byte of the string.
// str: pointer to the string
// str_len: length of the string
// to_skip: pointer to array of bytes/chars to be skipped
// 		Each byte/char is going to be skipped.
// to_skip_len: length of to_skip array
// Returns pointer to first byte in string not contained in bytes to skip.
// Does assert of str and to_skip.
// If str_len or to_skip_len is 0 str is returned.
// If all bytes/chars are skipped it returns pointer to the fisrt byte after
// the string.
const uint8_t *skip_sel_bytes(const uint8_t *str, size_t str_len,
	const uint8_t *to_skip, size_t to_skip_len);

// Splits string (NOT NULL TERMINATED C-STRING) into tokens according to given
// separators. Each token in saved in output array of token structs.
// str: pointer to the string
// str_len: length of the string
// tokens: start pointer to array of token structs
// tokens_len: length of token structs array
// separators: pointer to array of bytes/chars
// 		Each byte/char is considered as a separator.
// sep_len: number of separators bytes/chars
// There can be more separators between two tokens. Separators before first and
// after last token are skipped. Caller is responsible for proper allocation
// and free of enough tokens structs. It is recomended to allocate memory for
// maximum number of tokens which can be found: str_len / 2.
// Returns number of found tokens.
size_t tokenize(uint8_t *str, size_t str_len, struct token *tokens, size_t tokens_len, uint8_t *separators, size_t sep_len);

// Event base logging callback handler. It is empty procedure to supress any
// logging of an event base. First, it must be set up using event_set_log_callback
// function to work.
void ev_base_discard_cb(int severity, const char *msg);

// Concats NULL terminated strings passed as arguments to one NULL terminated string.
// buff: address of pointer to resulting string
// args_num: number of strings to concat
// 		Strings folllows as variable number of arguments.
// First, it allocates exact needed memory at *buff address. Caller is responsible
// for freeing allocated memory after using the string pointed by *buff.
void concat_mesg(char **buff, size_t args_num, ...);

// SIGINT signal event base handler. Given event base is only broken inside
// this procedure. First, it must be set up as callback to SIGINT signal by
// event_new or event_aasign to work properly.
void on_sigint(evutil_socket_t sig, short events, void *user_data);

// Validates whether given buffer can be decoded as UTF-8 string NOT containing
// NULL characters.
// buff: pointer to the buffer
// len: buffer length
// It uses naive implementation of canonical UTF-8 automaton from:
// https://bjoern.hoehrmann.de/utf-8/decoder/dfa/.
// If data represents UTF-8 string and do NOT contain NULL byte(s) it returns 0
// otherwise -1 is returned.
int check_serv_data(const uint8_t *buff, size_t len);

#endif /*__SENTINEL_MINIPOT_UTILS_H__*/
